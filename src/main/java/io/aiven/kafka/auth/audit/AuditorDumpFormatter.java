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

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Formatter for audit dump.
 */
public interface AuditorDumpFormatter {
    /**
     * Converts the given {@code dump} as log entries.
     *
     * @param dump the dump
     * @return the log entries
     */
    List<String> format(Map<Auditor.AuditKey, UserActivity> dump);

    static DateTimeFormatter dateFormatter() {
        return DateTimeFormatter.ISO_INSTANT;
    }

    default String formatUserOperation(final UserOperation userOperation) {
        return (userOperation.hasAccess ? "Allow" : "Deny")
                + " " + userOperation.operation.name() + " on "
                + userOperation.resource.resourceType() + ":"
                + userOperation.resource.name();
    }

}
