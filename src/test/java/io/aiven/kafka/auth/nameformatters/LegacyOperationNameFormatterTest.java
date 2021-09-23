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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class LegacyOperationNameFormatterTest {
    @Test
    void testFormatting() {
        assertThat(LegacyOperationNameFormatter.format(AclOperation.UNKNOWN)).isEqualTo("Unknown");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.ANY)).isEqualTo("Any");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.ALL)).isEqualTo("All");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.READ)).isEqualTo("Read");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.WRITE)).isEqualTo("Write");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.CREATE)).isEqualTo("Create");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.DELETE)).isEqualTo("Delete");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.ALTER)).isEqualTo("Alter");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.DESCRIBE)).isEqualTo("Describe");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.CLUSTER_ACTION)).isEqualTo("ClusterAction");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.DESCRIBE_CONFIGS)).isEqualTo("DescribeConfigs");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.ALTER_CONFIGS)).isEqualTo("AlterConfigs");
        assertThat(LegacyOperationNameFormatter.format(AclOperation.IDEMPOTENT_WRITE)).isEqualTo("IdempotentWrite");
    }
}
