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

import org.apache.kafka.common.resource.ResourceType;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

public class ResourceTypeParserTest {
    @Test
    public final void parseResourceTypeSingle() {
        assertThat(ResourceTypeParser.parse("^Topic$"))
            .containsExactly(ResourceType.TOPIC);
    }

    @Test
    public final void parseResourceTypeSingleWithParens() {
        assertThat(ResourceTypeParser.parse("^(Topic)$"))
            .containsExactly(ResourceType.TOPIC);
    }

    @Test
    public final void parseResourceTypeMultiple() {
        // List all possible here, apart from Unknown.
        assertThat(ResourceTypeParser.parse("^(Any|Topic|Group|Cluster|TransactionalId|DelegationToken)$"))
            .containsExactly(
                ResourceType.ANY,
                ResourceType.TOPIC,
                ResourceType.GROUP,
                ResourceType.CLUSTER,
                ResourceType.TRANSACTIONAL_ID,
                ResourceType.DELEGATION_TOKEN
            );
    }

    @ParameterizedTest
    @ValueSource(strings = {"^(.*)$", "^.*$"})
    public final void parseResourceTypeGlobalWildcard(final String value) {
        assertThat(ResourceTypeParser.parse(value))
            .containsExactly(
                ResourceType.TOPIC,
                ResourceType.GROUP,
                ResourceType.CLUSTER,
                ResourceType.TRANSACTIONAL_ID,
                ResourceType.DELEGATION_TOKEN
            );
    }

    @Test
    public final void parseResourceTypeUnknown() {
        assertThat(ResourceTypeParser.parse("^(Some)$"))
            .isEmpty();
    }

    @Test
    public final void parseResourceTypeNull() {
        assertThat(ResourceTypeParser.parse(null))
            .isEmpty();
    }

    @Test
    public final void parseResourceTypeMultipleWithUnknown() {
        assertThat(ResourceTypeParser.parse("^(Topic|Cluster|Some)$"))
            .containsExactly(ResourceType.TOPIC, ResourceType.CLUSTER);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "^(Topic|Cluster)",
        "(Topic|Cluster)$",
        "^(Topic|Cluster",
        "Topic|Cluster)$"
    })
    public final void parseResourceTypeInvalid(final String pattern) {
        assertThat(ResourceTypeParser.parse(pattern))
            .isEmpty();
    }
}
