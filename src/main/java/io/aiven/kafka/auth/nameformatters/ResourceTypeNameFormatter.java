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

import org.apache.kafka.common.resource.ResourceType;

public class ResourceTypeNameFormatter {
    public static ResourceType format(final String resourceType) {
        switch (resourceType) {
            case "Unknown":
                return ResourceType.UNKNOWN;

            case "Any":
                return ResourceType.ANY;

            case "Topic":
                return ResourceType.TOPIC;

            case "Group":
                return ResourceType.GROUP;

            case "Cluster":
                return ResourceType.CLUSTER;

            case "TransactionalId":
                return ResourceType.TRANSACTIONAL_ID;

            case "DelegationToken":
                return ResourceType.DELEGATION_TOKEN;

            default:
                return ResourceType.UNKNOWN;
        }
    }
}
