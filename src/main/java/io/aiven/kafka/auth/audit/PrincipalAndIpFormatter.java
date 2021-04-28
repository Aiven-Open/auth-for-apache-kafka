/*
 * Copyright 2021 Aiven Oy https://aiven.io
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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * An {@link AuditorDumpFormatter} that creates an entry for each IP
 * of each principal.
 */
public class PrincipalAndIpFormatter implements AuditorDumpFormatter {
    PrincipalAndIpFormatter() {
    }

    @Override
    public List<String> format(final Map<Auditor.AuditKey, UserActivity> dump) {
        return dump.entrySet().stream()
                .map(e -> auditMessagePrincipalAndSourceIp(e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }

    private String auditMessagePrincipalAndSourceIp(final Auditor.AuditKey key, final UserActivity userActivity) {
        final StringBuilder auditMessage = new StringBuilder(key.principal.toString());
        auditMessage
                .append(" (").append(key.sourceIp).append(")")
                .append(" was active since ")
                .append(userActivity.activeSince.format(AuditorDumpFormatter.dateFormatter()));
        if (userActivity.hasOperations()) {
            auditMessage.append(": ")
                    .append(userActivity
                            .operations
                            .stream()
                            .map(this::userOperationMessage)
                            .collect(Collectors.joining(", ")));
        }
        return auditMessage.toString();
    }

    private String userOperationMessage(final UserOperation op) {
        return (op.hasAccess ? "Allow" : "Deny")
                + " " + op.operation.name() + " on "
                + op.resource.resourceType() + ":"
                + op.resource.name();
    }
}
