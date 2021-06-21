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

import java.util.Map;
import java.util.Objects;

import org.apache.kafka.common.config.ConfigException;

import kafka.network.RequestChannel;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.slf4j.Logger;

public class UserActivityAuditor extends Auditor {

    public UserActivityAuditor() {
        super();
    }

    @Override
    public void configure(final Map<String, ?> configs) {
        super.configure(configs);
        if (auditorConfig.getAggregationGrouping() == AuditorConfig.AggregationGrouping.USER) {
            throw new ConfigException("Grouping by " + AuditorConfig.AggregationGrouping.USER.getConfigValue()
                    + " is not supported for this type of auditor");
        }
    }

    protected UserActivityAuditor(final Logger logger) {
        super(logger);
    }

    @Override
    protected void addActivity0(final RequestChannel.Session session,
                                final Operation operation,
                                final Resource resource,
                                final boolean hasAccess) {
        final AuditKey auditKey = new AuditKey(session.principal(), session.clientAddress());

        auditStorage.compute(auditKey, (key, userActivity) -> Objects.isNull(userActivity)
                ? new UserActivity.UserActivityOperations()
                : userActivity
        );
    }

    @Override
    protected AuditorDumpFormatter createFormatter() {
        return new PrincipalAndIpFormatter();
    }
}
