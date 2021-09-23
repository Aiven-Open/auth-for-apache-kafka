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

import org.apache.kafka.common.resource.ResourceType;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class LegacyResourceTypeNameFormatterTest {
    @Test
    void testFormatting() {
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.UNKNOWN)).isEqualTo("Unknown");
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.ANY)).isEqualTo("Any");
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.TOPIC)).isEqualTo("Topic");
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.GROUP)).isEqualTo("Group");
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.CLUSTER)).isEqualTo("Cluster");
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.TRANSACTIONAL_ID)).isEqualTo("TransactionalId");
        assertThat(LegacyResourceTypeNameFormatter.format(ResourceType.DELEGATION_TOKEN)).isEqualTo("DelegationToken");
    }
}
