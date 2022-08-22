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

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclPermissionType;

import io.aiven.kafka.auth.json.AivenAcl;

public class AclAivenToNativeConverter {
    public static Iterable<AclBinding> convert(final List<AivenAcl> aivenAcls) {
        final List<AclBinding> result = new ArrayList<>();

        for (final var aclEntry : aivenAcls) {
            if (!Objects.equals(aclEntry.principalType, "User")) {
                continue;
            }

            for (final var operation : AclOperationsParser.parse(aclEntry.operationRe.pattern())) {
                List<String> principals = RegexParser.parse(aclEntry.principalRe.pattern());
                if (principals == null) {
                    principals = List.of(aclEntry.principalRe.pattern());
                }
                for (final var principal : principals) {
                    final var accessControlEntry = new AccessControlEntry(
                        principal, "*", operation, AclPermissionType.ALLOW);
                    for (final var resourcePattern : ResourcePatternParser.parse(aclEntry.resourceRe.pattern())) {
                        result.add(new AclBinding(resourcePattern, accessControlEntry));
                    }
                }
            }
        }

        return result;
    }
}
