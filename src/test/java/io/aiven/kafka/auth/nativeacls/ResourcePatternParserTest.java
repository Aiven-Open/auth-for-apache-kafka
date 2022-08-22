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

import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

public class ResourcePatternParserTest {
    @ParameterizedTest
    @ValueSource(strings = {"^(.*)$", "^.*$"})
    public final void parseResourcePatternGlobalWildcard(final String value) {
        assertThat(ResourcePatternParser.parse(value))
            .containsExactly(
                new ResourcePattern(ResourceType.TOPIC, "^.*$", PatternType.LITERAL),
                new ResourcePattern(ResourceType.GROUP, "^.*$", PatternType.LITERAL),
                new ResourcePattern(ResourceType.CLUSTER, "^.*$", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TRANSACTIONAL_ID, "^.*$", PatternType.LITERAL),
                new ResourcePattern(ResourceType.DELEGATION_TOKEN, "^.*$", PatternType.LITERAL)
            );
    }

    @ParameterizedTest
    @ValueSource(strings = {"^Cluster:(.*)$", "^Cluster:.*$"})
    public final void parseResourcePatternSingleResourceTypeWildcard(final String value) {
        assertThat(ResourcePatternParser.parse(value))
            .containsExactly(new ResourcePattern(ResourceType.CLUSTER, ".*", PatternType.LITERAL));
    }

    @ParameterizedTest
    @ValueSource(strings = {"^TransactionalId:(xxx)$", "^TransactionalId:xxx$"})
    public final void parseResourcePatternSingleResourceTypeSingleResource(final String value) {
        assertThat(ResourcePatternParser.parse(value))
            .containsExactly(new ResourcePattern(ResourceType.TRANSACTIONAL_ID, "xxx", PatternType.LITERAL));
    }

    @Test
    public final void parseResourcePatternSingleResourceTypeMultipleResource() {
        assertThat(ResourcePatternParser.parse("^Topic:(xxx|yyy|bac.*xyz)$"))
            .containsExactly(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, "yyy", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, "bac.*xyz", PatternType.LITERAL)
            );
    }

    @Test
    public final void parseResourcePatternMultipleResourceTypeWildcard() {
        assertThat(ResourcePatternParser.parse("^(Cluster|Topic):(.*)$"))
            .containsExactly(
                new ResourcePattern(ResourceType.CLUSTER, ".*", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, ".*", PatternType.LITERAL)
            );
    }

    @ParameterizedTest
    @ValueSource(strings = {"^(Cluster|Topic):(xxx)$", "^(Cluster|Topic):xxx$"})
    public final void parseResourcePatternMultipleResourceTypeSingleResource(final String value) {
        assertThat(ResourcePatternParser.parse(value))
            .containsExactly(
                new ResourcePattern(ResourceType.CLUSTER, "xxx", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL)
            );
    }

    @Test
    public final void parseResourcePatternMultipleResourceTypeMultipleResource() {
        assertThat(ResourcePatternParser.parse("^(Cluster|Topic):(xxx|yyy|bac.*xyz)$"))
            .containsExactly(
                new ResourcePattern(ResourceType.CLUSTER, "xxx", PatternType.LITERAL),
                new ResourcePattern(ResourceType.CLUSTER, "yyy", PatternType.LITERAL),
                new ResourcePattern(ResourceType.CLUSTER, "bac.*xyz", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, "yyy", PatternType.LITERAL),
                new ResourcePattern(ResourceType.TOPIC, "bac.*xyz", PatternType.LITERAL)
            );
    }


    @ParameterizedTest
    @ValueSource(strings = {
        "^(AAA|BBB|CCC|DDD)",
        "(AAA|BBB|CCC|DDD)$",
        "^(AAA|BBB|CCC|DDD",
        "AAA|BBB|CCC|DDD)$",
        "^Cluster$",
        "^Cluster:$",
        "^:xxx$",
    })
    public final void parseResourcePatternInvalid(final String pattern) {
        assertThat(ResourcePatternParser.parse(pattern))
            .isEmpty();
    }

    @Test
    public final void parseResourcePatternNull() {
        assertThat(ResourcePatternParser.parse(null))
            .isEmpty();
    }
}
