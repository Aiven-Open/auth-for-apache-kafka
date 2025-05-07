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
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;

import io.aiven.kafka.auth.nameformatters.ResourceTypeNameFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResourcePatternParser {
    private static final Pattern PARSER_PATTERN = Pattern.compile("\\^\\(?(.*?)\\)?:\\(?(.*?)\\)?\\$");
    private static final Logger LOGGER = LoggerFactory.getLogger(ResourcePatternParser.class);

    // Visible for test

    static Iterable<ResourcePattern> parse(final String resourcePattern) {
        if (resourcePattern == null) {
            return List.of();
        }

        if (resourcePattern.equals("^.*$") || resourcePattern.equals("^(.*)$")) {
            return List.of(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new ResourcePattern(ResourceType.GROUP, "*", PatternType.LITERAL),
                new ResourcePattern(ResourceType.CLUSTER, "*", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TRANSACTIONAL_ID, "*", PatternType.LITERAL),
                new ResourcePattern(ResourceType.DELEGATION_TOKEN, "*", PatternType.LITERAL)
            );
        }

        final Matcher matcher = PARSER_PATTERN.matcher(resourcePattern);
        if (!matcher.find() || matcher.groupCount() != 2) {
            LOGGER.debug("Nothing parsed from resource pattern {}", resourcePattern);
            return List.of();
        }
        final String resourceTypesGroup = matcher.group(1);
        final String resourcesGroup = matcher.group(2);
        if (resourceTypesGroup.isBlank() || resourcesGroup.isBlank()) {
            LOGGER.debug("Parsed empty resource type or resource for {}", resourcePattern);
            return List.of();
        }
        final List<ResourceType> resourceTypes = Arrays.stream(resourceTypesGroup.split("\\|"))
            .flatMap(type -> ResourceTypeParser.parse(type).stream())
            .collect(Collectors.toList());

        final List<String> resources = Arrays.stream(resourcesGroup.split("\\|"))
            .filter(Predicate.not(String::isBlank))
            .collect(Collectors.toList());

        final List<ResourcePattern> result = new ArrayList<>(resourceTypes.size() * resources.size());
        for (final ResourceType resourceType : resourceTypes) {
            for (final String resource : resources) {
                result.add(createResourcePattern(resourceType, resource));
            }
        }
        return result;
    }

    public static List<ResourceType> parseResourceTypes(final String resourcePattern) {
        if (resourcePattern == null) {
            return List.of();
        }
        if (resourcePattern.equals("^.*$") || resourcePattern.equals("^(.*)$")) {
            return List.of(
                ResourceType.TOPIC,
                ResourceType.GROUP,
                ResourceType.CLUSTER,
                ResourceType.TRANSACTIONAL_ID,
                ResourceType.DELEGATION_TOKEN
            );
        }

        final Matcher matcher = PARSER_PATTERN.matcher(resourcePattern);
        if (!matcher.find() || matcher.groupCount() != 2) {
            LOGGER.debug("Nothing parsed from resource pattern {}", resourcePattern);
            return List.of();
        }
        final String resourceTypesGroup = matcher.group(1);
        if (resourceTypesGroup.isBlank()) {
            LOGGER.debug("Parsed empty resource type for {}", resourcePattern);
            return List.of();
        }
        final List<ResourceType> resourceTypes = new ArrayList<>();
        for (final String type : resourceTypesGroup.split("\\|")) {
            resourceTypes.add(ResourceTypeNameFormatter.format(type));
        }
        return resourceTypes;
    }

    private static Optional<ResourcePattern> parseSerializedResource(
        final String resourcePattern,
        final PatternType patternType
    ) {
        if (resourcePattern == null) {
            return Optional.empty();
        }
        final String[] parts = resourcePattern.split(":", 2);
        if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
            LOGGER.debug("Invalid format for resource literal '{}'", resourcePattern);
            return Optional.empty();
        }
        return Optional.of(new ResourcePattern(
                ResourceTypeNameFormatter.format(parts[0]),
                parts[1],
                patternType));
    }

    public static Optional<ResourcePattern> parseLiteral(final String resourcePattern) {
        return parseSerializedResource(resourcePattern, PatternType.LITERAL);
    }

    public static Optional<ResourcePattern> parsePrefixed(final String resourcePattern) {
        return parseSerializedResource(resourcePattern, PatternType.PREFIXED);
    }

    private static ResourcePattern createResourcePattern(final ResourceType resourceType, final String resource) {
        if (resource.equals(".*") || resource.equals("(.*)")) {
            return new ResourcePattern(resourceType, "*", PatternType.LITERAL);
        } else if (resource.endsWith("(.*)")) {
            return new ResourcePattern(
                resourceType, resource.substring(0, resource.length() - 4), PatternType.PREFIXED
            );
        } else {
            return new ResourcePattern(resourceType, resource, PatternType.LITERAL);
        }
    }
}
