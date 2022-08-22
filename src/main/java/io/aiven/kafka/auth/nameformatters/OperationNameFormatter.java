/*
 * Copyright 2022 Aiven Oy https://aiven.io
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

public class OperationNameFormatter {
    public static AclOperation format(final String operation) {
        switch (operation) {
            case "Unknown":
                return AclOperation.UNKNOWN;

            case "Any":
                return AclOperation.ANY;

            case "All":
                return AclOperation.ALL;

            case "Read":
                return AclOperation.READ;

            case "Write":
                return AclOperation.WRITE;

            case "Create":
                return AclOperation.CREATE;

            case "Delete":
                return AclOperation.DELETE;

            case "Alter":
                return AclOperation.ALTER;

            case "Describe":
                return AclOperation.DESCRIBE;

            case "ClusterAction":
                return AclOperation.CLUSTER_ACTION;

            case "DescribeConfigs":
                return AclOperation.DESCRIBE_CONFIGS;

            case "AlterConfigs":
                return AclOperation.ALTER_CONFIGS;

            case "IdempotentWrite":
                return AclOperation.IDEMPOTENT_WRITE;

            default:
                return AclOperation.UNKNOWN;
        }
    }
}
