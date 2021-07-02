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

import java.util.Objects;

import kafka.network.RequestChannel;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.slf4j.Logger;

public class UserOperationsActivityAuditor extends Auditor {

    public UserOperationsActivityAuditor() {
        super();
    }

    protected UserOperationsActivityAuditor(final Logger logger) {
        super(logger);
    }

    @Override
    protected void addActivity0(final RequestChannel.Session session,
                                final Operation operation,
                                final Resource resource,
                                final boolean hasAccess) {
        auditStorage.compute(createAuditKey(session), (key, userActivity) -> {
            final UserActivity ua;
            if (Objects.isNull(userActivity)) {
                ua = createUserActivity();
            } else {
                ua = userActivity;
            }
            ua.addOperation(new UserOperation(session.clientAddress(), operation, resource, hasAccess));
            return ua;
        });
    }

    private AuditKey createAuditKey(final RequestChannel.Session session) {
        final var grouping = auditorConfig.getAggregationGrouping();
        switch (grouping) {
            case USER:
                return new AuditKey(session.principal(), null);
            case USER_AND_IP:
                return new AuditKey(session.principal(), session.clientAddress());
            default:
                throw new IllegalArgumentException("Unknown aggregation grouping type: " + grouping);
        }
    }

    private UserActivity createUserActivity() {
        final var grouping = auditorConfig.getAggregationGrouping();
        switch (grouping) {
            case USER:
                return new UserActivity.UserActivityOperationsGropedByIP();
            case USER_AND_IP:
                return new UserActivity.UserActivityOperations();
            default:
                throw new IllegalArgumentException("Unknown aggregation grouping type: " + grouping);
        }
    }

    @Override
    protected AuditorDumpFormatter createFormatter() {
        final var grouping = auditorConfig.getAggregationGrouping();
        switch (grouping) {
            case USER:
                return new PrincipalFormatter();
            case USER_AND_IP:
                return new PrincipalAndIpFormatter();
            default:
                throw new IllegalArgumentException("Unknown aggregation grouping type: " + grouping);
        }
    }
}
