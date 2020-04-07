/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.net.InetAddress;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Auditor implements Configurable {

    private final Logger logger;

    protected Map<AuditKey, UserActivity> auditStorage = new HashMap<>();

    private final Lock auditLock = new ReentrantLock();

    private final ScheduledExecutorService auditScheduler =
        Executors.newScheduledThreadPool(1);

    public Auditor() {
        this.logger = LoggerFactory.getLogger("aiven.auditor.logger");
    }

    // visible for test
    protected Auditor(final Logger logger) {
        this.logger = logger;
    }

    @Override
    public void configure(final Map<String, ?> configs) {
        final AuditorConfig auditorConfig = new AuditorConfig(configs);
        auditScheduler.scheduleAtFixedRate(
            this::dump,
            auditorConfig.getAggregationPeriodInSeconds(),
            auditorConfig.getAggregationPeriodInSeconds(),
            TimeUnit.SECONDS
        );
    }

    public void addActivity(final Session session,
                            final Operation operation,
                            final Resource resource,
                            final Boolean hasAccess) {

        final AuditKey auditKey = new AuditKey(session.principal(), session.clientAddress());
        auditLock.lock();
        try {
            auditStorage.compute(auditKey, (key, userActivity) -> {
                if (Objects.isNull(userActivity)) {
                    return onUserActivity(new UserActivity(), operation, resource, hasAccess);
                } else {
                    return onUserActivity(userActivity, operation, resource, hasAccess);
                }
            });
        } finally {
            auditLock.unlock();
        }
    }

    public void stop() {
        auditScheduler.shutdownNow();
        dump();
    }

    protected void dump() {
        final Map<AuditKey, UserActivity> auditStorageDump;
        auditLock.lock();
        try {
            auditStorageDump = auditStorage;
            auditStorage = new HashMap<>();
        } finally {
            auditLock.unlock();
        }
        auditStorageDump.forEach((key, userActivity) -> logger.info(auditMessage(key, userActivity)));
    }

    private String auditMessage(final AuditKey key, final UserActivity userActivity) {
        final StringBuilder auditMessage = new StringBuilder(key.principal.toString());
        auditMessage
            .append(" (").append(key.sourceIp).append(")")
            .append(" was active since ")
            .append(userActivity.activeSince.format(DateTimeFormatter.ISO_INSTANT));
        if (userActivity.hasOperations()) {
            auditMessage.append(": ")
                .append(
                    userActivity
                        .operations
                        .stream()
                        .map(this::userOperationMessage)
                        .collect(Collectors.joining(", "))
                );
        }
        return auditMessage.toString();
    }

    private String userOperationMessage(final UserOperation op) {
        return (op.hasAccess ? "Allow" : "Deny")
            + " " + op.operation.name() + " on "
            + op.resource.resourceType() + ":"
            + op.resource.name();
    }

    protected abstract UserActivity onUserActivity(final UserActivity userActivity,
                                                   final Operation operation,
                                                   final Resource resource,
                                                   final Boolean hasAccess);

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
