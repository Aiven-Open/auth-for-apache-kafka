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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.audit.AuditorAPI;
import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.json.reader.AclJsonReader;
import io.aiven.kafka.auth.json.reader.JsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Acl;
import kafka.security.auth.Authorizer;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Deprecated
public class AivenAclAuthorizer implements Authorizer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AivenAclAuthorizer.class);
    private File configFile;
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private long lastUpdateCheckTimestamp = 0;
    private long lastModifiedTimestamp = 0;
    private List<AivenAcl> aclEntries;
    private Map<String, Boolean> verdictCache;
    private JsonReader<AivenAcl> jsonReader;
    private AuditorAPI auditor;
    private boolean logDenials;

    public AivenAclAuthorizer() {
    }

    /**
     * Reload ACLs from disk under a write lock.
     */
    public boolean reloadAcls() {
        lock.writeLock().lock();
        final long previousUpdate = lastModifiedTimestamp;
        try {
            checkAndUpdateConfig();
            lastUpdateCheckTimestamp = System.nanoTime() / 1000000;
            return previousUpdate != lastModifiedTimestamp;
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void configure(final java.util.Map<String, ?> configs) {
        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(configs);

        auditor = config.getAuditor();
        logDenials = config.logDenials();

        configFile = config.getConfigFile();
        jsonReader = new AclJsonReader(configFile.toPath());
        checkAndUpdateConfig();
    }

    /**
     * Read config file and populate ACL entries, if the config file has changed.
     * This function assumes appropriate synchronization by caller.
     */
    private void checkAndUpdateConfig() {
        final long configFileLastModified = configFile.lastModified();

        if (configFileLastModified != lastModifiedTimestamp) {
            LOGGER.info("Reloading ACL configuration {}", configFile);
            try {
                final List<AivenAcl> newAclEntries = jsonReader.read();
                // initialize cache for non-trivial ACLs
                if (newAclEntries.size() > 10) {
                    if (verdictCache != null) {
                        verdictCache.clear();
                    } else {
                        verdictCache = new ConcurrentHashMap<>();
                    }
                } else {
                    verdictCache = null;
                }
                aclEntries = newAclEntries;
            } catch (final JsonReaderException ex) {
                LOGGER.error("Failed to load config file", ex);
            }
        }
        lastModifiedTimestamp = configFileLastModified;
    }

    @Override
    public void close() {
        auditor.stop();
    }

    @Override
    public boolean authorize(final Session session,
                             final Operation operation,
                             final Resource resource) {
        final KafkaPrincipal principal =
            Objects.nonNull(session.principal())
                ? session.principal()
                : KafkaPrincipal.ANONYMOUS;
        final String resourceToCheck =
            resource.resourceType() + ":" + resource.name();
        final boolean verdict =
            checkAcl(
                principal.getPrincipalType(),
                principal.getName(),
                operation.name(),
                resourceToCheck
            );
        auditor.addActivity(session, operation.toJava(), resource.toPattern(), verdict);
        return verdict;
    }

    /**
     * Authorize a single request.
     */
    //FIXME split code here in functions !!!!!
    private boolean checkAcl(final String principalType,
                             final String principalName,
                             final String operation,
                             final String resource) {
        final long now = System.nanoTime() / 1000000; // nanoTime is monotonic, convert to milliseconds
        boolean verdict = false;
        String cacheKey = null;

        // only ever try to cache user matches
        if (principalType.equals(KafkaPrincipal.USER_TYPE)) {
            cacheKey = resource + "|" + operation + "|" + principalName + "|" + principalType;
        }

        // we loop here until we can evaluate the access with fresh configuration
        while (true) {
            // First, check if we have a fresh config, and if so, evaluate access request
            lock.readLock().lock();
            try {
                if (lastUpdateCheckTimestamp + 10000 > now) {
                    if (cacheKey != null && verdictCache != null) {
                        final Boolean cachedVerdict = verdictCache.get(cacheKey);
                        if (cachedVerdict != null) {
                            verdict = cachedVerdict.booleanValue();
                            logAuthVerdict(verdict, operation, resource, principalType, principalName, true);
                            return verdict;
                        }
                    }

                    final Iterator<AivenAcl> iter = aclEntries.iterator();
                    while (!verdict && iter.hasNext()) {
                        final AivenAcl aclEntry = iter.next();
                        if (aclEntry.check(principalType, principalName, operation, resource)) {
                            verdict = true;
                        }
                    }
                    logAuthVerdict(verdict, operation, resource, principalType, principalName, false);
                    if (cacheKey != null && verdictCache != null) {
                        verdictCache.put(cacheKey, verdict);
                    }
                    return verdict;
                }
            } finally {
                lock.readLock().unlock();
            }

            // We may need to update the config
            lock.writeLock().lock();
            try {
                // Recheck the timer, as an another thread may have updated config
                // while we waited for the lock.
                if (lastUpdateCheckTimestamp + 10000 <= now) {
                    lastUpdateCheckTimestamp = now;
                    checkAndUpdateConfig();
                }
            } finally {
                lock.writeLock().unlock();
            }
        }
    }

    private void logAuthVerdict(final boolean verdict,
                                final String operation,
                                final String resource,
                                final String principalType,
                                final String principalName,
                                final boolean cached) {
        final String cachedStr = cached ? " (cached)" : "";
        if (verdict) {
            LOGGER.debug("[ALLOW] Auth request {} on {} by {} {}{}",
                    operation, resource, principalType, principalName, cachedStr);
        } else {
            if (logDenials) {
                LOGGER.info("[DENY] Auth request {} on {} by {} {}{}",
                        operation, resource, principalType, principalName, cachedStr);
            } else {
                LOGGER.debug("[DENY] Auth request {} on {} by {} {}{}",
                        operation, resource, principalType, principalName, cachedStr);
            }
        }
    }

    @Override
    public scala.collection.immutable.Set<Acl> getAcls(final Resource resource) {
        LOGGER.error("getAcls(Resource) is not implemented");
        return new scala.collection.immutable.HashSet<Acl>();
    }

    @Override
    public scala.collection.immutable.Map<Resource, scala.collection.immutable.Set<Acl>> getAcls(
        final KafkaPrincipal principal) {
        LOGGER.error("getAcls(KafkaPrincipal) is not implemented");
        return new scala.collection.immutable.HashMap<Resource, scala.collection.immutable.Set<Acl>>();
    }

    @Override
    public scala.collection.immutable.Map<Resource, scala.collection.immutable.Set<Acl>> getAcls() {
        LOGGER.error("getAcls() is not implemented");
        return new scala.collection.immutable.HashMap<Resource, scala.collection.immutable.Set<Acl>>();
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
