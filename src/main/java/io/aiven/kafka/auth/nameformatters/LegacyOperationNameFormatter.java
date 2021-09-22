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

package io.aiven.kafka.auth.nameformatters;

import org.apache.kafka.common.acl.AclOperation;

public final class LegacyOperationNameFormatter {
    public static String format(final AclOperation operation) {
        switch (operation) {
            case UNKNOWN:
                return "Unknown";

            case ANY:
                return "Any";

            case ALL:
                return "All";

            case READ:
                return "Read";

            case WRITE:
                return "Write";

            case CREATE:
                return "Create";

            case DELETE:
                return "Delete";

            case ALTER:
                return "Alter";

            case DESCRIBE:
                return "Describe";

            case CLUSTER_ACTION:
                return "ClusterAction";

            case DESCRIBE_CONFIGS:
                return "DescribeConfigs";

            case ALTER_CONFIGS:
                return "AlterConfigs";

            case IDEMPOTENT_WRITE:
                return "IdempotentWrite";

            default:
                // In case there's an unknown operation, fall back to the slow path.
                return LegacyNameFormatter.format(operation.name());
        }
    }
}
