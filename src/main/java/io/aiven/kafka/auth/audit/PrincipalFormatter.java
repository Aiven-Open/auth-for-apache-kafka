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

import java.net.InetAddress;
import java.time.ZonedDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

/**
 * An {@link AuditorDumpFormatter} that creates one entry per principal,
 * having info of each IP address in that entry.
 */
public class PrincipalFormatter implements AuditorDumpFormatter {
    @Override
    public List<String> format(final Map<Auditor.AuditKey, UserActivity> dump) {
        return dump.keySet().stream()
                .map(k -> k.principal)
                .sorted(Comparator.comparing(KafkaPrincipal::toString))
                .distinct()
                .map(principal -> {
                    final Map<Auditor.AuditKey, UserActivity> principalActivities = dump.entrySet().stream()
                            .filter(e -> e.getKey().principal.equals(principal))
                            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));


                    return auditMessagePrincipal(principal, principalActivities);
                })
                .collect(Collectors.toList());
    }

    private String auditMessagePrincipal(final KafkaPrincipal principal,
                                         final Map<Auditor.AuditKey, UserActivity> principalActivities) {
        final ZonedDateTime earliest = principalActivities.values().stream()
                .map(ua -> ua.activeSince)
                .sorted()
                .findFirst()
                .get();

        final StringBuilder auditMessage = new StringBuilder(principal.toString());
        auditMessage
                .append(" was active since ")
                .append(earliest.format(AuditorDumpFormatter.dateFormatter()))
                .append(".");

        final String allActivities = principalActivities.entrySet().stream()
                .map(e -> {
                    final InetAddress sourceIp = e.getKey().sourceIp;
                    final UserActivity userActivity = e.getValue();
                    final List<String> operations = userActivity.operations.stream().map(op ->
                            (op.hasAccess ? "Allow" : "Deny")
                                    + " " + op.operation.name() + " on "
                                    + op.resource.resourceType() + ":"
                                    + op.resource.name()
                    ).collect(Collectors.toList());

                    final StringBuilder sb = new StringBuilder();
                    sb.append(sourceIp.toString());
                    if (!operations.isEmpty()) {
                        sb.append(": ");
                        sb.append(String.join(", ", operations));
                    }
                    return sb.toString();
                })
                .collect(Collectors.joining(", "));
        if (!allActivities.isBlank()) {
            auditMessage.append(" ");
            auditMessage.append(allActivities);
        }

        return auditMessage.toString();
    }

}
