/*
 * Copyright 2020 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth.audit;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Auditor implements AuditorAPI {

    private final Logger logger;

    protected Map<AuditKey, UserActivity> auditStorage = new HashMap<>();

    private final Lock auditLock = new ReentrantLock();

    private final ScheduledExecutorService auditScheduler = Executors.newScheduledThreadPool(1);

    protected AuditorConfig auditorConfig;

    public Auditor() {
        this(LoggerFactory.getLogger("aiven.auditor.logger"));
    }

    // visible for test
    protected Auditor(final Logger logger) {
        this.logger = logger;
    }

    @Override
    public void configure(final Map<String, ?> configs) {
        auditorConfig = new AuditorConfig(configs);
        auditScheduler.scheduleAtFixedRate(
            this::dump,
            auditorConfig.getAggregationPeriodInSeconds(),
            auditorConfig.getAggregationPeriodInSeconds(),
            TimeUnit.SECONDS
        );
    }

    @Override
    public final void addActivity(final Session session,
                                  final Operation operation,
                                  final Resource resource,
                                  final boolean hasAccess) {
        auditLock.lock();
        try {
            addActivity0(session, operation, resource, hasAccess);
        } finally {
            auditLock.unlock();
        }
    }

    protected abstract void addActivity0(final Session session,
                                         final Operation operation,
                                         final Resource resource,
                                         final boolean hasAccess);

    @Override
    public void stop() {
        dump();
        auditScheduler.shutdownNow();
        try {
            auditScheduler.awaitTermination(5, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            // Intentionally ignored
        }
    }

    protected void dump() {
        try {
            createFormatter().format(makeDump()).forEach(logger::info);
        } catch (final Exception e) {
            logger.warn("Couldn't dump messages", e);
        }
    }

    private Map<AuditKey, UserActivity> makeDump() {
        final Map<AuditKey, UserActivity> auditStorageDump;
        auditLock.lock();
        try {
            auditStorageDump = auditStorage;
            auditStorage = new HashMap<>();
        } finally {
            auditLock.unlock();
        }
        return auditStorageDump;
    }

    protected abstract AuditorDumpFormatter createFormatter();

    protected static class AuditKey {

        public final KafkaPrincipal principal;

        public final InetAddress sourceIp;

        protected AuditKey(final KafkaPrincipal principal, final InetAddress sourceIp) {
            this.principal = principal;
            this.sourceIp = sourceIp;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof AuditKey)) {
                return false;
            }
            final AuditKey auditKey = (AuditKey) o;
            return Objects.equals(principal, auditKey.principal)
                && Objects.equals(sourceIp, auditKey.sourceIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(principal, sourceIp);
        }

    }
}
