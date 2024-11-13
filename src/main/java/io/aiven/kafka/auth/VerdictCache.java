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

package io.aiven.kafka.auth;

import javax.annotation.Nonnull;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.json.AclPermissionType;
import io.aiven.kafka.auth.json.AivenAcl;

public class VerdictCache {
    private final List<AivenAcl> allowAclEntries;
    private final List<AivenAcl> denyAclEntries;
    private final Map<String, Boolean> cache = new ConcurrentHashMap<>();

    private VerdictCache(@Nonnull final List<AivenAcl> denyAclEntries, @Nonnull final List<AivenAcl> allowAclEntries) {
        this.denyAclEntries = denyAclEntries;
        this.allowAclEntries = allowAclEntries;
    }

    public boolean get(
        final KafkaPrincipal principal,
        final String host,
        final AclOperation operation,
        final String resource
    ) {
        final String principalType = principal.getPrincipalType();
        final String cacheKey = resource
            + "|" + operation
            + "|" + host
            + "|" + principal.getName()
            + "|" + principalType;

        return cache.computeIfAbsent(cacheKey, key -> {
            final Predicate<AivenAcl> matcher = acl ->
                acl.match(principalType, principal.getName(), host, operation, resource);
            if (denyAclEntries.stream().anyMatch(matcher)) {
                return false;
            } else {
                return allowAclEntries.stream().anyMatch(matcher);
            }
        });
    }

    public Stream<AivenAcl> aclEntries() {
        return Stream.concat(denyAclEntries.stream(), allowAclEntries.stream());
    }

    public static VerdictCache create(final List<AivenAcl> aclEntries) {
        if (aclEntries == null || aclEntries.isEmpty()) {
            return new VerdictCache(Collections.emptyList(), Collections.emptyList());
        }

        final Map<Boolean, List<AivenAcl>> partitionedEntries = aclEntries.stream()
            .collect(Collectors.partitioningBy(x -> x.getPermissionType() == AclPermissionType.DENY));
        return new VerdictCache(partitionedEntries.get(true), partitionedEntries.get(false));
    }
}
