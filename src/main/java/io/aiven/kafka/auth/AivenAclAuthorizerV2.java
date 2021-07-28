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
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.audit.AuditorAPI;
import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.json.reader.AclJsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Acl;
import kafka.security.auth.Authorizer;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
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
        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(configs);

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
    public boolean authorize(final Session session,
                             final Operation operation,
                             final Resource resource) {
        final KafkaPrincipal principal =
                Objects.requireNonNullElse(session.principal(), KafkaPrincipal.ANONYMOUS);
        final String resourceToCheck =
            resource.resourceType() + ":" + resource.name();
        final boolean verdict =
            checkAcl(
                principal.getPrincipalType(),
                principal.getName(),
                operation.name(),
                resourceToCheck
            );
        auditor.addActivity(session, operation, resource, verdict);
        return verdict;
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
                             final String resource) {

        final boolean verdict = cacheReference.get().get(principalType, principalName, operation, resource);
        logAuthVerdict(verdict, operation, resource, principalType, principalName);
        return verdict;
    }

    private void logAuthVerdict(final boolean verdict,
                                final String operation,
                                final String resource,
                                final String principalType,
                                final String principalName) {
        if (verdict) {
            LOGGER.debug("[ALLOW] Auth request {} on {} by {} {}",
                    operation, resource, principalType, principalName);
        } else {
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
    public scala.collection.immutable.Set<Acl> getAcls(final Resource resource) {
        LOGGER.error("getAcls(Resource) is not implemented");
        return new scala.collection.immutable.HashSet<>();
    }

    @Override
    public scala.collection.immutable.Map<Resource, scala.collection.immutable.Set<Acl>> getAcls(
            final KafkaPrincipal principal) {
        LOGGER.error("getAcls(KafkaPrincipal) is not implemented");
        return new scala.collection.immutable.HashMap<>();
    }

    @Override
    public scala.collection.immutable.Map<Resource, scala.collection.immutable.Set<Acl>> getAcls() {
        LOGGER.error("getAcls() is not implemented");
        return new scala.collection.immutable.HashMap<>();
    }

    @Override
    public boolean removeAcls(final scala.collection.immutable.Set<Acl> acls,
                              final Resource resource) {
        LOGGER.error("removeAcls(Set<Acl>, Resource) is not implemented");
        return false;
    }

    @Override
    public boolean removeAcls(final Resource resource) {
        LOGGER.error("removeAcls(Resource) is not implemented");
        return false;
    }

    @Override
    public void addAcls(final scala.collection.immutable.Set<Acl> acls,
                        final Resource resource) {
        LOGGER.error("addAcls(Set<Acl>, Resource) is not implemented");
    }
}
