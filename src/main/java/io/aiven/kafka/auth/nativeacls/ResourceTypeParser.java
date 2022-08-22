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

package io.aiven.kafka.auth.nativeacls;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.kafka.common.resource.ResourceType;

import io.aiven.kafka.auth.nameformatters.ResourceTypeNameFormatter;

class ResourceTypeParser {
    // Visible for test
    static List<ResourceType> parse(final String resourceTypePattern) {
        if (resourceTypePattern == null) {
            return List.of();
        }

        if (resourceTypePattern.equals("^.*$") || resourceTypePattern.equals("^(.*)$")) {
            return List.of(
                ResourceType.TOPIC,
                ResourceType.GROUP,
                ResourceType.CLUSTER,
                ResourceType.TRANSACTIONAL_ID,
                ResourceType.DELEGATION_TOKEN
            );
        }

        final List<String> parsedResourceTypeList = RegexParser.parse(resourceTypePattern);
        if (parsedResourceTypeList == null) {
            return List.of();
        }

        return parsedResourceTypeList.stream()
            .map(ResourceTypeNameFormatter::format)
            .filter(rt -> rt != ResourceType.UNKNOWN)
            .collect(Collectors.toList());
    }
}
