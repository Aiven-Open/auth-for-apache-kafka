/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.util.Map;

import kafka.network.RequestChannel;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;

public class NoAuditor extends Auditor {

    public NoAuditor() {
        super();
    }

    @Override
    protected UserActivity onUserActivity(final UserActivity userActivity,
                                          final Operation operation,
                                          final Resource resource,
                                          final Boolean hasAccess) {
        return userActivity;
    }

    @Override
    public void addActivity(final RequestChannel.Session session,
                            final Operation operation,
                            final Resource resource,
                            final Boolean hasAccess) {
    }

    @Override
    public void configure(final Map<String, ?> map) {
    }

    @Override
    public void stop() {
    }
}
