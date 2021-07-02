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
 * An {@link AuditorDumpFormatter} that creates one entry per principal,
 * having info of each IP address in that entry.
 */
public class PrincipalFormatter implements AuditorDumpFormatter {
    @Override
    public List<String> format(final Map<Auditor.AuditKey, UserActivity> dump) {
        return dump.entrySet().stream()
                .map(e -> buildAuditMessage(e.getKey(), (UserActivity.UserActivityOperationsGropedByIP) e.getValue()))
                .collect(Collectors.toList());
    }

    private String buildAuditMessage(final Auditor.AuditKey auditKey,
                                     final UserActivity.UserActivityOperationsGropedByIP userActivity) {
        final var auditMessage = new StringBuilder(auditKey.principal.toString())
                .append(" was active since ")
                .append(userActivity.activeSince.format(AuditorDumpFormatter.dateFormatter()))
                .append(".");
        if (!userActivity.operations.isEmpty()) {
            auditMessage.append(" ");
            auditMessage.append(
                    userActivity
                            .operations.entrySet().stream()
                            .map(e -> {
                                final var operations = new StringBuilder();
                                operations.append(e.getKey()).append(": ");
                                operations.append(
                                        e.getValue().stream()
                                                .map(this::formatUserOperation)
                                                .collect(Collectors.joining(", "))
                                );
                                return operations.toString();
                            }).collect(Collectors.joining(", "))
            );
        }
        return auditMessage.toString();
    }

}
