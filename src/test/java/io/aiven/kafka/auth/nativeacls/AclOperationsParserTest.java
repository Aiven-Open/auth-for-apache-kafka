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

import org.apache.kafka.common.acl.AclOperation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

public class AclOperationsParserTest {
    @Test
    public final void parseAclOperationsSingle() {
        assertThat(AclOperationsParser.parse("^Create$"))
            .containsExactly(AclOperation.CREATE);
    }

    @Test
    public final void parseAclOperationsSingleWithParens() {
        assertThat(AclOperationsParser.parse("^(Create)$"))
            .containsExactly(AclOperation.CREATE);
    }

    @Test
    public final void parseAclOperationsMultiple() {
        // List all possible here, apart from Unknown.
        final String operationPattern = "^(Any|All|Read|Write|Create|Delete|Alter|Describe|"
            + "ClusterAction|DescribeConfigs|AlterConfigs|IdempotentWrite)$";
        assertThat(AclOperationsParser.parse(operationPattern))
            .containsExactly(
                AclOperation.ANY,
                AclOperation.ALL,
                AclOperation.READ,
                AclOperation.WRITE,
                AclOperation.CREATE,
                AclOperation.DELETE,
                AclOperation.ALTER,
                AclOperation.DESCRIBE,
                AclOperation.CLUSTER_ACTION,
                AclOperation.DESCRIBE_CONFIGS,
                AclOperation.ALTER_CONFIGS,
                AclOperation.IDEMPOTENT_WRITE
            );
    }

    @ParameterizedTest
    @ValueSource(strings = {"^(.*)$", "^.*$"})
    public final void parseAclOperationsGlobalWildcard(final String value) {
        assertThat(AclOperationsParser.parse(value))
            .containsExactly(
                AclOperation.READ,
                AclOperation.WRITE,
                AclOperation.CREATE,
                AclOperation.DELETE,
                AclOperation.ALTER,
                AclOperation.DESCRIBE,
                AclOperation.CLUSTER_ACTION,
                AclOperation.DESCRIBE_CONFIGS,
                AclOperation.ALTER_CONFIGS,
                AclOperation.IDEMPOTENT_WRITE
            );
    }

    @Test
    public final void parseAclOperationsSingleUnknown() {
        assertThat(AclOperationsParser.parse("^(Some)$"))
            .isEmpty();
    }

    @Test
    public final void parseAclOperationsNull() {
        assertThat(AclOperationsParser.parse(null))
            .isEmpty();
    }

    @Test
    public final void parseAclOperationsMultipleWithUnknown() {
        assertThat(AclOperationsParser.parse("^(Create|Describe|AlterConfigs|Some)$"))
            .containsExactly(
                AclOperation.CREATE,
                AclOperation.DESCRIBE,
                AclOperation.ALTER_CONFIGS);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "^(Create|Delete)",
        "(Create|Delete)$",
        "^(Create|Delete",
        "Create|Delete)$"
    })
    public final void parseAclOperationsInvalid(final String pattern) {
        assertThat(AclOperationsParser.parse(pattern))
            .isEmpty();
    }
}
