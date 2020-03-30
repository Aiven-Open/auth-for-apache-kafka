/**
 * Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Acl;
import kafka.security.auth.Authorizer;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AivenAclAuthorizer implements Authorizer {
    private static final Logger LOGGER = LoggerFactory.getLogger(AivenAclAuthorizer.class);
    private String configFileLocation;
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private long lastUpdateCheckTimestamp = 0;
    private long lastModifiedTimestamp = 0;
    private List<AivenAclEntry> aclEntries;
    private Map<String, Boolean> verdictCache;

    public AivenAclAuthorizer() {
    }

    /**
     * Read config file and populate ACL entries, if the config file has changed.
     * This function assumes appropriate synchronization by caller.
     */
    private void checkAndUpdateConfig() {
        final File configFile = new File(configFileLocation);
        final long configFileLastModified = configFile.lastModified();

        if (configFileLastModified != lastModifiedTimestamp) {
            LOGGER.info("Reloading ACL configuration {}", configFileLocation);
            final List<AivenAclEntry> newAclEntries = new ArrayList<>();
            final JSONParser parser = new JSONParser();
            try {
                final Object obj = parser.parse(new FileReader(configFile));
                final JSONArray root = (JSONArray) obj;
                final Iterator<JSONObject> iter = root.iterator();
                while (iter.hasNext()) {
                    final JSONObject node = iter.next();
                    newAclEntries.add(
                        new AivenAclEntry(
                            (String) node.get("principal_type"),
                            (String) node.get("principal"),
                            (String) node.get("operation"),
                            (String) node.get("resource"),
                            (String) node.get("resource_pattern")
                        )
                    );
                }

                // initialize cache for non-trivial ACLs
                if (newAclEntries.size() > 10) {
                    if (verdictCache != null) {
                        verdictCache.clear();
                    } else {
                        verdictCache = new ConcurrentHashMap<String, Boolean>();
                    }
                } else {
                    verdictCache = null;
                }

                aclEntries = newAclEntries;
            } catch (final IOException | ParseException ex) {
                LOGGER.error("Failed to read configuration file", ex);
            }
        }
        lastModifiedTimestamp = configFileLastModified;
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
        configFileLocation = (String) configs.get("aiven.acl.authorizer.configuration");
        checkAndUpdateConfig();
    }

    @Override
    public void close() {
    }

    @Override
    public boolean authorize(final Session session,
                             final Operation operationObj,
                             final Resource resourceObj) {
        KafkaPrincipal principal = session.principal();
        if (principal == null) {
            principal = KafkaPrincipal.ANONYMOUS;
        }

        final String principalName = principal.getName();
        final String principalType = principal.getPrincipalType();
        final String operation = operationObj.name();
        final String resource = resourceObj.resourceType() + ":" + resourceObj.name();

        return checkAcl(principalType, principalName, operation, resource);
    }

    /**
     * Authorize a single request.
     */
    //FIXME split code here in functions !!!!!
    public boolean checkAcl(final String principalType,
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
                            if (verdict) {
                                LOGGER.debug("[ALLOW] Auth request {} on {} by {} {} (cached)",
                                    operation, resource, principalType, principalName);
                            } else {
                                LOGGER.info("[DENY] Auth request {} on {} by {} {} (cached)",
                                    operation, resource, principalType, principalName);
                            }
                            return verdict;
                        }
                    }

                    final Iterator<AivenAclEntry> iter = aclEntries.iterator();
                    while (!verdict && iter.hasNext()) {
                        final AivenAclEntry aclEntry = iter.next();
                        if (aclEntry.check(principalType, principalName, operation, resource)) {
                            verdict = true;
                        }
                    }
                    if (verdict) {
                        LOGGER.debug("[ALLOW] Auth request {} on {} by {} {}",
                            operation, resource, principalType, principalName);
                    } else {
                        LOGGER.info("[DENY] Auth request {} on {} by {} {}",
                            operation, resource, principalType, principalName);
                    }
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
