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

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;

import io.aiven.kafka.auth.json.AivenAcl;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AclAivenToNativeConverterTest {
    @Test
    public final void testConvertSimple() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(test\\-user)$",
                "^(Alter|AlterConfigs|Delete|Read|Write)$",
                "^Topic:(xxx)$",
                null,
                io.aiven.kafka.auth.json.AclPermissionType.ALLOW
            )
        );
        final ResourcePattern resourcePattern = new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL);
        assertThat(result).containsExactly(
            new AclBinding(
                resourcePattern,
                new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER, AclPermissionType.ALLOW)),
            new AclBinding(
                resourcePattern,
                new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER_CONFIGS, AclPermissionType.ALLOW)),
            new AclBinding(
                resourcePattern,
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DELETE, AclPermissionType.ALLOW)),
            new AclBinding(
                resourcePattern,
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)),
            new AclBinding(
                resourcePattern,
                new AccessControlEntry("User:test\\-user", "*", AclOperation.WRITE, AclPermissionType.ALLOW))
        );
    }

    @Test
    public final void testNullPermissionTypeIsAllow() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(test\\-user)$",
                "^Read$",
                "^Topic:(xxx)$",
                null,
                null
            )
        );
        final ResourcePattern resourcePattern = new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL);
        assertThat(result).containsExactly(
            new AclBinding(
                resourcePattern,
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW))
        );
    }

    @Test
    public final void testConvertPrefix() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(test\\-user)$",
                "^Read$",
                "^Topic:(topic\\.(.*))$",
                null,
                null
            )
        );
        assertThat(result).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "topic\\.", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)
            )
        );
    }

    @Test
    public final void testDeny() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(test\\-user)$",
                "^Read$",
                "^Topic:(topic\\.(.*))$",
                null,
                io.aiven.kafka.auth.json.AclPermissionType.DENY
            )
        );
        assertThat(result).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "topic\\.", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.DENY)
            )
        );
    }

    @Test
    public final void testConvertMultiplePrefixes() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(test\\-user)$",
                "^(Delete|Read|Write)$",
                "^Topic:(topic\\.(.*)|prefix\\-(.*))$",
                null,
                null
            )
        );
        assertThat(result).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "topic\\.", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DELETE, AclPermissionType.ALLOW)
            ),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "prefix\\-", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DELETE, AclPermissionType.ALLOW)
            ),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "topic\\.", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)
            ),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "prefix\\-", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)
            ),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "topic\\.", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.WRITE, AclPermissionType.ALLOW)
            ),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "prefix\\-", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.WRITE, AclPermissionType.ALLOW)
            )
        );
    }

    @Test
    public final void testSuperadmin() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(admin)$",
                "^(.*)$",
                "^(.*)$",
                null,
                null
            )
        );

        final List<AclBinding> expected = new ArrayList<>();
        final List<ResourceType> expectedResourceTypes = List.of(
            ResourceType.TOPIC, ResourceType.GROUP, ResourceType.CLUSTER,
            ResourceType.TRANSACTIONAL_ID, ResourceType.DELEGATION_TOKEN);
        final List<AclOperation> expectedAclOperations = List.of(
            AclOperation.READ, AclOperation.WRITE, AclOperation.CREATE,
            AclOperation.DELETE, AclOperation.ALTER, AclOperation.DESCRIBE,
            AclOperation.CLUSTER_ACTION, AclOperation.DESCRIBE_CONFIGS,
            AclOperation.ALTER_CONFIGS, AclOperation.IDEMPOTENT_WRITE);
        for (final var resourceType : expectedResourceTypes) {
            for (final var aclOperation : expectedAclOperations) {
                expected.add(new AclBinding(
                    new ResourcePattern(resourceType, "*", PatternType.LITERAL),
                    new AccessControlEntry("User:admin", "*", aclOperation, AclPermissionType.ALLOW))
                );
            }
        }
        assertThat(result).containsAll(expected);
    }

    @Test
    public final void testAllUsers() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "User",
                "^(.*)$",
                "^Read$",
                "^Topic:(xxx)$",
                null,
                null
            )
        );

        assertThat(result).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:*", "*", AclOperation.READ, AclPermissionType.ALLOW)
            )
        );
    }

    @Test
    public final void testNoUserPrincipalType() {
        final var result = AclAivenToNativeConverter.convert(
            new AivenAcl(
                "Group",
                "^example$",
                "^Read$",
                "^Topic:(xxx)$",
                null,
                null
            )
        );

        assertThat(result).isEmpty();
    }
}
