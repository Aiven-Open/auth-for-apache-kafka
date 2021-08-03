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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

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

public class LocklessAivenAclAuthorizer implements Authorizer {

    private static final Logger LOGGER = LoggerFactory.getLogger(AivenAclAuthorizer.class);
    private File configFile;
    private AtomicReference<List<AivenAcl>> aclEntries = new AtomicReference<>();
    private Map<String, Boolean> verdictCache;
    private JsonReader<AivenAcl> jsonReader;
    private AuditorAPI auditor;
    private boolean logDenials;
    private final Object lock = new Object();

    // A `stat` system call is needed to check if the configuration was
    // updated. Because that is expensive changes to the file are checked only
    // so often. This is the timestamp of the last time the configuration was
    // checked for modification.
    private long lastCheckTimestamp = 0;

    // The modified timestamp is used to infer if the file contents changed.
    private long lastModifiedTimestamp = 0;

    public LocklessAivenAclAuthorizer() {
        verdictCache = new ConcurrentHashMap<>();
    }

    /**
     * Reload ACLs from disk.
     */
    public boolean reloadAcls() {
        final boolean changed = reloadConfigIfNecessary();
        lastCheckTimestamp = getTimestamp();
        return changed;
    }

    @Override
    public void configure(final java.util.Map<String, ?> configs) {
        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(configs);

        auditor = config.getAuditor();
        logDenials = config.logDenials();

        configFile = config.getConfigFile();
        jsonReader = new AclJsonReader(configFile.toPath());
        reloadConfigIfNecessary();
    }

    private long getTimestamp() {
        return System.nanoTime() / 1000000;  // nanoTime is monotonic, convert to milliseconds
    }

    private boolean isTimeToCheckConfig(final long now) {
        return lastCheckTimestamp + 10000 <= now;
    }

    /**
     * If the modified timestamp of the file changed, reload it and populate ACL entries.
     */
    private boolean reloadConfigIfNecessary() {
        // Note about synchronization with the files system: It is possible for
        // the configuration file to be updated *while* we are doing an update.
        // These are a the assumptions on how the system interacts to prevent
        // errors:
        // - The filesystem must update the mtime *after* the files contents.
        // So at worst case we will have an older modified time and read the
        // file twice. Otherwise we would read the new timestamp with the old
        // content and the rules would be out-of-date.
        // - The new contents should be exposed atomicaly, partial updates will
        // cause parse errors.
        // - The update of lastModifiedTimestamp and aclEntries must be
        // performed exclusively. Otherwise it is possible for two threads to
        // read two different versions of the configuration, and it is possible
        // to end up with the new modified timestamp, but the old configuration
        // loaded.
        synchronized (lock) {
            final long configFileLastModified = configFile.lastModified();
            final boolean changed = configFileLastModified != lastModifiedTimestamp;

            if (changed) {
                // Note: It is okay for the statements below to be reordered:
                // - clearing the cache
                // - setting the new ACL rules
                // the assumption that stale results are acceptable for a short
                // period of time.
                lastModifiedTimestamp = configFileLastModified;

                LOGGER.info("Reloading ACL configuration {}", configFile);
                try {
                    final List<AivenAcl> newAclEntries = jsonReader.read();
                    aclEntries.set(newAclEntries);
                    verdictCache.clear();
                } catch (final JsonReaderException ex) {
                    LOGGER.error("Failed to load config file", ex);
                }
            }

            return changed;
        }
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
        auditor.addActivity(session, operation, resource, verdict);
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
        final long now = getTimestamp();

        // Note: lastCheckTimestamp is not being synchronzied, so it is
        // possible that multiple threads will reload the configuration. This
        // should be fine since the contents of the file will be paged. The
        // only downside is that its content may be parsed a few times.
        if (isTimeToCheckConfig(now)) {
            lastCheckTimestamp = now;
            reloadConfigIfNecessary();
        }

        // ACLs are defined by a list of rules with regular expressions. The
        // current implementation must do a linear search over all the existing
        // rules and for each rule check if the Regexes match the current user.
        // Depending on the number of rules this can be a slow process, so the
        // result is cached.
        final String cacheKey = resource + "|" + operation + "|" + principalName + "|" + principalType;

        // Assumptions about concurrency:
        // - Because there is no mechanism to atomically update the
        // configuration, polling is used.
        // - Because the update is performed with polling, there will be a
        // period of time were the ruleset is updated in the filesystem, but
        // not yet seen by the authorizer. For that length of time the results
        // are stale (with or without the usage of a cache).
        // - Because of the above stale results are assumed to be okay, as long
        // as the configuration is eventually updated (in a timely manner).

        final Boolean cachedVerdict = verdictCache.get(cacheKey);
        if (cachedVerdict != null) {
            logAuthVerdict(cachedVerdict.booleanValue(), operation, resource, principalType, principalName, true);
            return cachedVerdict.booleanValue();
        }

        boolean verdict = false;
        for (final var aclEntry : aclEntries.get()) {
            if (aclEntry.check(principalType, principalName, operation, resource)) {
                verdict = true;
                break;
            }
        }
        logAuthVerdict(verdict, operation, resource, principalType, principalName, false);
        verdictCache.put(cacheKey, verdict);
        return verdict;
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

