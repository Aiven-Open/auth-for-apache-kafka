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
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;

import io.aiven.kafka.auth.json.AivenAcl;

public class AclAivenToNativeConverter {
    public static List<AclBinding> convert(final AivenAcl aivenAcl) {
        final List<AclBinding> result = new ArrayList<>();
        if (aivenAcl.resourceRePattern != null) {
            return result;
        }

        if (!Objects.equals(aivenAcl.principalType, "User")) {
            return result;
        }

        final Iterable<AclOperation> operations = aivenAcl.operations != null
             ? aivenAcl.operations.stream().map(o -> o.nativeType).collect(Collectors.toList())
             : AclOperationsParser.parse(aivenAcl.operationRe.pattern());

        for (final var operation : operations) {
            final List<String> principals = AclPrincipalFormatter.parse(
                aivenAcl.principalType, aivenAcl.principalRe.pattern()
            );
            for (final var principal : principals) {
                final var accessControlEntry = new AccessControlEntry(
                    principal, aivenAcl.getHostMatcher(), operation, aivenAcl.getPermissionType().nativeType);
                if (aivenAcl.resourceRe != null) {
                    for (final var resourcePattern : ResourcePatternParser.parse(aivenAcl.resourceRe.pattern())) {
                        result.add(new AclBinding(resourcePattern, accessControlEntry));
                    }
                } else if (aivenAcl.resourceLiteral != null) {
                    ResourcePatternParser.parseLiteral(aivenAcl.resourceLiteral).ifPresent(
                            resourcePattern -> result.add(new AclBinding(resourcePattern, accessControlEntry))
                    );
                } else if (aivenAcl.resourcePrefix != null) {
                    ResourcePatternParser.parsePrefixed(aivenAcl.resourcePrefix).ifPresent(
                            resourcePattern -> result.add(new AclBinding(resourcePattern, accessControlEntry))
                    );
                }
            }
        }

        return result;
    }
}
