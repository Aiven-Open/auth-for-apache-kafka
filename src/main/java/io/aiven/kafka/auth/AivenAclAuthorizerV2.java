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
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.server.authorizer.AclCreateResult;
import org.apache.kafka.server.authorizer.AclDeleteResult;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.Authorizer;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;

import io.aiven.kafka.auth.audit.AuditorAPI;
import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.json.reader.AclJsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AivenAclAuthorizerV2 implements Authorizer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AivenAclAuthorizerV2.class);
    private File configFile;
    private AuditorAPI auditor;
    private boolean logDenials;
    private final ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
    private final WatchService watchService;
    private final AtomicReference<VerdictCache> cacheReference = new AtomicReference<>();

    private AivenAclAuthorizerConfig config;

    public AivenAclAuthorizerV2() {
        try {
            watchService = FileSystems.getDefault().newWatchService();
        } catch (final IOException e) {
            LOGGER.error("Failed to initialize WatchService", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void configure(final java.util.Map<String, ?> configs) {
        config = new AivenAclAuthorizerConfig(configs);
    }

    @Override
    public final Map<Endpoint, ? extends CompletionStage<Void>> start(
        final AuthorizerServerInfo serverInfo) {
        auditor = config.getAuditor();
        logDenials = config.logDenials();

        configFile = config.getConfigFile();
        final AclJsonReader jsonReader = new AclJsonReader(configFile.toPath());
        cacheReference.set(VerdictCache.create(loadAcls(jsonReader)));
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
                    cacheReference.set(VerdictCache.create(loadAcls(jsonReader)));
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
            // Some string conversions are done inside.
            final var operation = Operation.fromJava(action.operation());
            final var resourceType = ResourceType.fromJava(action.resourcePattern().resourceType());
            final String resourceToCheck =
                resourceType + ":" + action.resourcePattern().name();
            final boolean verdict =
                checkAcl(
                    principal.getPrincipalType(),
                    principal.getName(),
                    operation.name(),
                    resourceToCheck,
                    action.logIfAllowed(),
                    action.logIfDenied()
                );

            // When we finally drop the old API, we can change the auditor API,
            // so it doesn't require these conversions.
            final var session = new Session(principal, requestContext.clientAddress());
            final var resource = new Resource(
                resourceType,
                action.resourcePattern().name(),
                action.resourcePattern().patternType());
            auditor.addActivity(session, operation, resource, verdict);

            result.add(verdict ? AuthorizationResult.ALLOWED : AuthorizationResult.DENIED);
        }
        return result;
    }

    /**
     * Read ACL entries from config file.
     */
    private List<AivenAcl> loadAcls(final AclJsonReader jsonReader) {
        LOGGER.info("Reloading ACL configuration...");
        try {
            return jsonReader.read();
        } catch (final JsonReaderException ex) {
            LOGGER.error("Failed to load ACL config file", ex);
            return Collections.emptyList();
        }
    }

    /**
     * Authorize a single request.
     */
    private boolean checkAcl(final String principalType,
                             final String principalName,
                             final String operation,
                             final String resource,
                             final boolean actionLogIfAllowed,
                             final boolean actionLogIfDenied) {
        final boolean verdict = cacheReference.get().get(principalType, principalName, operation, resource);
        logAuthVerdict(verdict, operation, resource, principalType, principalName,
            actionLogIfAllowed, actionLogIfDenied);
        return verdict;
    }

    private void logAuthVerdict(final boolean verdict,
                                final String operation,
                                final String resource,
                                final String principalType,
                                final String principalName,
                                final boolean actionLogIfAllowed,
                                final boolean actionLogIfDenied) {
        if (verdict && actionLogIfAllowed) {
            LOGGER.debug("[ALLOW] Auth request {} on {} by {} {}",
                    operation, resource, principalType, principalName);
        } else if (actionLogIfDenied) {
            if (logDenials) {
                LOGGER.info("[DENY] Auth request {} on {} by {} {}",
                        operation, resource, principalType, principalName);
            } else {
                LOGGER.debug("[DENY] Auth request {} on {} by {} {}",
                        operation, resource, principalType, principalName);
            }
        }
    }

    @Override
    public final List<? extends CompletionStage<AclCreateResult>> createAcls(
        final AuthorizableRequestContext requestContext,
        final List<AclBinding> aclBindings) {
        LOGGER.error("`createAcls` is not implemented");
        return List.of();
    }

    @Override
    public final List<? extends CompletionStage<AclDeleteResult>> deleteAcls(
        final AuthorizableRequestContext requestContext,
        final List<AclBindingFilter> aclBindingFilters) {
        LOGGER.error("`deleteAcls` is not implemented");
        return List.of();
    }

    @Override
    public final Iterable<AclBinding> acls(final AclBindingFilter filter) {
        LOGGER.error("`acls` is not implemented");
        return List.of();
    }
}
