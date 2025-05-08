/*
 * Copyright 2019 Aiven Oy https://aiven.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.aiven.kafka.auth;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.metrics.MetricConfig;
import org.apache.kafka.common.metrics.Sensor;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.server.authorizer.AclCreateResult;
import org.apache.kafka.server.authorizer.AclDeleteResult;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.Authorizer;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;

import io.aiven.kafka.auth.audit.AuditorAPI;
import io.aiven.kafka.auth.audit.Session;
import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.json.reader.AclJsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;
import io.aiven.kafka.auth.nameformatters.LegacyResourceTypeNameFormatter;
import io.aiven.kafka.auth.nativeacls.AclAivenToNativeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.aiven.kafka.auth.AivenAclAuthorizerConfig.METRICS_NUM_SAMPLES_CONFIG;
import static io.aiven.kafka.auth.AivenAclAuthorizerConfig.METRICS_RECORDING_LEVEL_CONFIG;
import static io.aiven.kafka.auth.AivenAclAuthorizerConfig.METRICS_SAMPLE_WINDOW_MS_CONFIG;

public class AivenAclAuthorizerV2 implements Authorizer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AivenAclAuthorizerV2.class);

    private File configFile;
    private AuditorAPI auditor;
    private boolean logDenials;
    private ScheduledExecutorService scheduledExecutorService;

    private volatile WatchService watchService;

    private final AtomicReference<VerdictCache> cacheReference = new AtomicReference<>();
    private final Time time;

    private AivenAclAuthorizerConfig config;
    private AivenAclAuthorizerMetrics metrics;

    public AivenAclAuthorizerV2() {
        this(Time.SYSTEM);
    }

    // for testing
    AivenAclAuthorizerV2(final Time time) {
        this.time = time;
    }

    @Override
    public void configure(final java.util.Map<String, ?> configs) {
        config = new AivenAclAuthorizerConfig(configs);

        final MetricConfig metricConfig = new MetricConfig()
            .samples(config.getInt(METRICS_NUM_SAMPLES_CONFIG))
            .timeWindow(config.getLong(METRICS_SAMPLE_WINDOW_MS_CONFIG), TimeUnit.MILLISECONDS)
            .recordLevel(Sensor.RecordingLevel.forName(config.getString(METRICS_RECORDING_LEVEL_CONFIG)));
        metrics = new AivenAclAuthorizerMetrics(time, metricConfig);
    }

    @Override
    public final Map<Endpoint, ? extends CompletionStage<Void>> start(
        final AuthorizerServerInfo serverInfo) {
        auditor = config.getAuditor();
        logDenials = config.logDenials();
        watchService = initializeWatchService();
        scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();

        configFile = config.getConfigFile();
        final AclJsonReader jsonReader = new AclJsonReader(configFile.toPath());
        cacheReference.set(VerdictCache.create(loadAcls(jsonReader), config.getCacheMaxSizePercentage(),
                config.getCacheExpireAfterAccess()));
        final AtomicReference<WatchKey> watchKeyReference = new AtomicReference<>(subscribeToAclChanges(configFile));
        scheduledExecutorService.scheduleWithFixedDelay(() -> {
            final WatchKey watchKey = watchKeyReference.get();
            if (watchKey != null) {
                final List<WatchEvent<?>> watchEvents = watchKey.pollEvents();

                watchEvents.stream().filter(watchEvent -> {
                    @SuppressWarnings("unchecked")
                    final Path path = ((WatchEvent<Path>) watchEvent).context();
                    return configFile.toPath().getFileName().equals(path);
                }).findFirst().ifPresent(watchEvent -> {
                    LOGGER.info("{}: {}, Modified: {}",
                            watchEvent.kind(), watchEvent.context(), configFile.lastModified());
                    cacheReference.set(VerdictCache.create(loadAcls(jsonReader), config.getCacheMaxSizePercentage(),
                            config.getCacheExpireAfterAccess()));
                });
                if (!watchKey.reset()) {
                    watchKeyReference.compareAndSet(watchKey, subscribeToAclChanges(configFile));
                }
            } else {
                watchKeyReference.set(subscribeToAclChanges(configFile));
            }
        }, 0, config.configRefreshInterval(), TimeUnit.MILLISECONDS);

        // These futures are just placeholders.
        return serverInfo.endpoints().stream()
            .collect(Collectors.toMap(
                endpoint -> endpoint,
                endpoint -> CompletableFuture.completedFuture(null)
            ));
    }

    private WatchService initializeWatchService() {
        try {
            return FileSystems.getDefault().newWatchService();
        } catch (final IOException e) {
            LOGGER.error("Failed to initialize WatchService", e);
            throw new RuntimeException(e);
        }
    }

    private WatchKey subscribeToAclChanges(final File configFile) {
        try {
            return configFile.toPath().toAbsolutePath().getParent()
                    .register(watchService, StandardWatchEventKinds.ENTRY_MODIFY,
                            StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE);
        } catch (final IOException e) {
            LOGGER.error("Failed to subscribe to ACL configuration changes", e);
            return null;
        }
    }

    @Override
    public void close() {
        auditor.stop();
        scheduledExecutorService.shutdownNow();
        try {
            watchService.close();
        } catch (final IOException e) {
            LOGGER.error("Failed to stop watch service", e);
        }
    }

    @Override
    public final List<AuthorizationResult> authorize(final AuthorizableRequestContext requestContext,
                                                     final List<Action> actions) {
        final KafkaPrincipal principal =
            Objects.requireNonNullElse(requestContext.principal(), KafkaPrincipal.ANONYMOUS);
        final List<AuthorizationResult> result = new ArrayList<>(actions.size());
        for (final Action action : actions) {
            final AclOperation operation = action.operation();
            final ResourcePattern resourcePattern = action.resourcePattern();
            final String resourceToCheck =
                LegacyResourceTypeNameFormatter.format(resourcePattern.resourceType())
                + ":" + resourcePattern.name();
            final String host = requestContext.clientAddress().getHostAddress();
            final boolean verdict = cacheReference.get().get(principal,
                                                             host,
                                                             operation,
                                                             resourceToCheck);
            final var authResult = verdict ? AuthorizationResult.ALLOWED : AuthorizationResult.DENIED;

            metrics.recordLogAuthResult(authResult, operation, resourcePattern, principal);
            logAuthVerdict(verdict, operation, resourcePattern, principal, requestContext,
                           action.logIfAllowed(), action.logIfDenied());

            final var session = new Session(principal, requestContext.clientAddress());
            auditor.addActivity(session, operation, resourcePattern, verdict);

            result.add(authResult);
        }
        return result;
    }

    /**
     * Check if the caller is authorized to perform the given ACL operation on at least one
     * resource of the given type.
     *
     * @param requestContext Request context including request resourceType, security protocol and listener name
     * @param op             The ACL operation to check
     * @param resourceType   The resource type to check
     * @return               Return {@link AuthorizationResult#ALLOWED} if the caller is authorized
     *                       to perform the given ACL operation on at least one resource of the
     *                       given type. Return {@link AuthorizationResult#DENIED} otherwise.
     */
    @Override
    public AuthorizationResult authorizeByResourceType(
        final AuthorizableRequestContext requestContext,
        final AclOperation op,
        final ResourceType resourceType) {
        final KafkaPrincipal principal =
            Objects.requireNonNullElse(requestContext.principal(), KafkaPrincipal.ANONYMOUS);

        final ResourcePattern resourcePattern = new ResourcePattern(resourceType, "", PatternType.LITERAL);

        final AuthorizationResult authResult = calculateAuthorizeByResourceType(
            requestContext, op, resourceType, principal);

        final boolean verdict = authResult == AuthorizationResult.ALLOWED;
        metrics.recordLogAuthResult(authResult, op, resourcePattern, principal);
        logAuthVerdict(verdict, op, resourcePattern, principal, requestContext,
                       false, false);

        return authResult;
    }

    // This is for benchmarking purposes only
    AuthorizationResult default_authorizeByResourceType(
        final AuthorizableRequestContext requestContext,
        final AclOperation op,
        final ResourceType resourceType) {
        return Authorizer.super.authorizeByResourceType(requestContext, op, resourceType);
    }

    private AuthorizationResult calculateAuthorizeByResourceType(
        final AuthorizableRequestContext requestContext,
        final AclOperation op,
        final ResourceType resourceType,
        final KafkaPrincipal principal) {

        final String principalType = principal.getPrincipalType();
        final String principalName = principal.getName();

        final EnumMap<PatternType, Set<String>> denyPatterns =
            new EnumMap<PatternType, Set<String>>(PatternType.class) {
                {
                    put(PatternType.LITERAL, new HashSet<>());
                    put(PatternType.PREFIXED, new HashSet<>());
                }
            };
        final EnumMap<PatternType, Set<String>> allowPatterns =
            new EnumMap<PatternType, Set<String>>(PatternType.class) {
                {
                    put(PatternType.LITERAL, new HashSet<>());
                    put(PatternType.PREFIXED, new HashSet<>());
                }
            };

        final String hostAddr = requestContext.clientAddress().getHostAddress();

        for (final AivenAcl acl : this.cacheReference.get().getDenyAclEntries()) {

            if (!acl.hostMatch(hostAddr)) {
                continue;
            }

            if (!acl.matchResourceType(resourceType)) {
                continue;
            }

            if (!acl.matchPrincipal(principalType, principalName)) {
                continue;
            }

            if (!acl.matchOperation(op)) {
                continue;
            }

            for (final AclBinding binding : AclAivenToNativeConverter.convert(acl)) {

                if (binding.pattern().patternType() == PatternType.LITERAL) {
                    // If wildcard deny exists, return deny directly
                    if (binding.pattern().name().equals(ResourcePattern.WILDCARD_RESOURCE)) {
                        return AuthorizationResult.DENIED;
                    }
                    denyPatterns.get(PatternType.LITERAL).add(binding.pattern().name());
                } else if (binding.pattern().patternType() == PatternType.PREFIXED) {
                    denyPatterns.get(PatternType.PREFIXED).add(binding.pattern().name());
                } else {
                    LOGGER.error("Unknown pattern type in deny rule: {}", binding.pattern().patternType());
                    return AuthorizationResult.DENIED;
                }
            }
        }

        for (final AivenAcl acl : this.cacheReference.get().getAllowAclEntries()) {

            if (!acl.hostMatch(hostAddr)) {
                continue;
            }

            if (!acl.matchResourceType(resourceType)) {
                continue;
            }

            if (!acl.matchPrincipal(principalType, principalName)) {
                continue;
            }

            if (!acl.matchOperation(op)) {
                continue;
            }

            for (final AclBinding binding : AclAivenToNativeConverter.convert(acl)) {

                if (binding.pattern().patternType() == PatternType.LITERAL) {
                    if (binding.pattern().name().equals(ResourcePattern.WILDCARD_RESOURCE)) {
                        return AuthorizationResult.ALLOWED;
                    }
                    allowPatterns.get(PatternType.LITERAL).add(binding.pattern().name());
                } else if (binding.pattern().patternType() == PatternType.PREFIXED) {
                    allowPatterns.get(PatternType.PREFIXED).add(binding.pattern().name());
                } else {
                    LOGGER.error("Unknown pattern type in allow rule: {}", binding.pattern().patternType());
                    // Pass through because it is safe to allow if any other rule allows
                    // the request.
                }
            }
        }

        // For any literal allowed, if there's no dominant literal and prefix denied,
        // return allow.
        // For any prefix allowed, if there's no dominant prefix denied, return allow.
        for (final Map.Entry<PatternType, Set<String>> entry : allowPatterns.entrySet()) {
            for (final String allowStr : entry.getValue()) {
                if (entry.getKey() == PatternType.LITERAL
                        && denyPatterns.get(PatternType.LITERAL).contains(allowStr)) {
                    continue;
                }
                final StringBuilder sb = new StringBuilder();
                boolean hasDominatedDeny = false;
                for (final char ch : allowStr.toCharArray()) {
                    sb.append(ch);
                    if (denyPatterns.get(PatternType.PREFIXED).contains(sb.toString())) {
                        hasDominatedDeny = true;
                        break;
                    }
                }
                if (!hasDominatedDeny) {
                    return AuthorizationResult.ALLOWED;
                }
            }
        }

        return AuthorizationResult.DENIED;
    }

    /**
     * Read ACL entries from config file.
     */
    private List<AivenAcl> loadAcls(final AclJsonReader jsonReader) {
        LOGGER.debug("Reloading ACL configuration...");
        try {
            return jsonReader.read();
        } catch (final JsonReaderException ex) {
            LOGGER.error("Failed to load ACL config file", ex);
            return Collections.emptyList();
        }
    }

    private void logAuthVerdict(final boolean verdict,
                                final AclOperation operation,
                                final ResourcePattern resourcePattern,
                                final KafkaPrincipal principal,
                                final AuthorizableRequestContext requestContext,
                                final boolean actionLogIfAllowed,
                                final boolean actionLogIfDenied) {
        if (verdict && actionLogIfAllowed) {
            LOGGER.debug("[ALLOW] Auth request {} on {}:{} by {} {} from {} ({})",
                operation.name(), resourcePattern.resourceType(), resourcePattern.name(),
                         principal.getPrincipalType(), principal.getName(),
                         requestContext.clientAddress().getHostAddress(),
                         requestContext.clientId());
        } else if (actionLogIfDenied) {
            if (logDenials) {
                LOGGER.info("[DENY] Auth request {} on {}:{} by {} {} from {} ({})",
                    operation.name(), resourcePattern.resourceType(), resourcePattern.name(),
                    principal.getPrincipalType(), principal.getName(),
                         requestContext.clientAddress().getHostAddress(),
                         requestContext.clientId());
            } else {
                LOGGER.debug("[DENY] Auth request {} on {}:{} by {} {} from {} ({})",
                    operation.name(), resourcePattern.resourceType(), resourcePattern.name(),
                    principal.getPrincipalType(), principal.getName(),
                         requestContext.clientAddress().getHostAddress(),
                         requestContext.clientId());
            }
        }
    }

    @Override
    public final List<? extends CompletionStage<AclCreateResult>> createAcls(
        final AuthorizableRequestContext requestContext,
        final List<AclBinding> aclBindings) {
        LOGGER.warn("`createAcls` is not implemented");
        return List.of();
    }

    @Override
    public final List<? extends CompletionStage<AclDeleteResult>> deleteAcls(
        final AuthorizableRequestContext requestContext,
        final List<AclBindingFilter> aclBindingFilters) {
        LOGGER.warn("`deleteAcls` is not implemented");
        return List.of();
    }

    @Override
    public final Iterable<AclBinding> acls(final AclBindingFilter filter) {
        if (this.config.listAclsEnabled()) {
            return this.cacheReference.get().aclEntries()
                    .filter(acl -> !acl.isHidden())
                    .flatMap(acl -> AclAivenToNativeConverter.convert(acl).stream())
                    .filter(filter::matches)
                    .collect(Collectors.toList());
        } else {
            LOGGER.warn("Listing ACLs is disabled");
            return List.of();
        }
    }

    final long getEstimatedCacheSizeEntries() {
        return cacheReference.get().getEstimatesSizeEntries();
    }
}
