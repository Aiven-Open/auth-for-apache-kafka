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

import java.util.ArrayList;
import java.util.List;

import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;

class ResourcePatternParser {
    // Visible for test
    static Iterable<ResourcePattern> parse(final String resourcePattern) {
        if (resourcePattern == null) {
            return List.of();
        }

        if (resourcePattern.equals("^.*$") || resourcePattern.equals("^(.*)$")) {
            final var resourcePatternNormalized = resourcePattern.equals("^(.*)$") ? "^.*$" : resourcePattern;
            return List.of(
                new ResourcePattern(ResourceType.TOPIC, resourcePatternNormalized, PatternType.LITERAL),
                new ResourcePattern(ResourceType.GROUP, resourcePatternNormalized, PatternType.LITERAL),
                new ResourcePattern(ResourceType.CLUSTER, resourcePatternNormalized, PatternType.LITERAL),
                new ResourcePattern(ResourceType.TRANSACTIONAL_ID, resourcePatternNormalized, PatternType.LITERAL),
                new ResourcePattern(ResourceType.DELEGATION_TOKEN, resourcePatternNormalized, PatternType.LITERAL)
            );
        }

        final String[] parts = resourcePattern.split(":");
        if (parts.length != 2) {
            return List.of();
        }

        // Normalize and parse the left part.
        final List<ResourceType> resourceTypes = parseResourceTypes(parts[0]);
        if (resourceTypes == null) {
            return List.of();
        }

        final List<String> resources = parseResources(parts[1]);
        if (resources == null) {
            return List.of();
        }

        final List<ResourcePattern> result = new ArrayList<>(resourceTypes.size() * resources.size());
        for (final ResourceType resourceType : resourceTypes) {
            for (final String resource : resources) {
                result.add(
                    new ResourcePattern(resourceType, resource, PatternType.LITERAL)
                );
            }
        }
        return result;
    }

    private static List<ResourceType> parseResourceTypes(String leftPart) {
        if (!leftPart.startsWith("^")) {
            return null;
        }
        if (leftPart.startsWith("^(")) {
            leftPart = leftPart.substring(2);
        } else {
            leftPart = leftPart.substring(1);
        }
        if (leftPart.endsWith(")")) {
            leftPart = leftPart.substring(0, leftPart.length() - 1);
        }
        leftPart = leftPart.trim();
        if (leftPart.isEmpty()) {
            return null;
        }
        return ResourceTypeParser.parse("^(" + leftPart + ")$");
    }

    private static List<String> parseResources(String rightPart) {
        if (!rightPart.endsWith("$")) {
            return null;
        }
        if (rightPart.endsWith(")$")) {
            rightPart = rightPart.substring(0, rightPart.length() - 2);
        } else {
            rightPart = rightPart.substring(0, rightPart.length() - 1);
        }
        if (rightPart.startsWith("(")) {
            rightPart = rightPart.substring(1);
        }
        rightPart = rightPart.trim();
        if (rightPart.isEmpty()) {
            return null;
        }

        return RegexParser.parse("^(" + rightPart + ")$");
    }
}
