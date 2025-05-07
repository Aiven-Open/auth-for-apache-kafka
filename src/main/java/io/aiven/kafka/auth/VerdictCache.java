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
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.json.AclPermissionType;
import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.utils.ObjectSizeEstimator;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

public class VerdictCache {
    private final List<AivenAcl> allowAclEntries;
    private final List<AivenAcl> denyAclEntries;
    private final Cache<String, Boolean> cache;


    private VerdictCache(@Nonnull final List<AivenAcl> denyAclEntries, @Nonnull final List<AivenAcl> allowAclEntries,
            final double maxSizePercentage, final int expireAfterAccessMinutes) {
        this.denyAclEntries = denyAclEntries;
        this.allowAclEntries = allowAclEntries;

        final long maxHeapSize = Runtime.getRuntime().maxMemory();
        final long maxSize = (long) ((maxHeapSize / 100) * maxSizePercentage);

        cache = Caffeine.newBuilder()
                .expireAfterAccess(expireAfterAccessMinutes, java.util.concurrent.TimeUnit.MINUTES)
                .maximumWeight(maxSize)
                .weigher((String key, Boolean value) -> {
                    final int keySize = ObjectSizeEstimator.estimateStringSize(key);
                    final int valueSize = ObjectSizeEstimator.estimateBooleanSize(value);
                    final int entrySize = keySize + valueSize + ObjectSizeEstimator.estimateEntryOverhead();
                    // 1.5x overhead for cache metadata, lazy initialization etc.
                    final int totalSize = (int) (entrySize * 1.5);
                    return totalSize;
                })
                .build();
    }

    public long getEstimatedSizeBytes() {
        final var eviction = cache.policy().eviction().orElseThrow();
        final long currentWeight = eviction.weightedSize().orElseThrow();
        return currentWeight;
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

        return cache.get(cacheKey, key -> {
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

    public List<AivenAcl> getAllowAclEntries() {
        return Collections.unmodifiableList(allowAclEntries);
    }

    public List<AivenAcl> getDenyAclEntries() {
        return Collections.unmodifiableList(denyAclEntries);
    }

    public static VerdictCache create(final List<AivenAcl> aclEntries, final double maxSizePercentage,
            final int expireAfterAccessMinutes) {
        if (aclEntries == null || aclEntries.isEmpty()) {
            return new VerdictCache(Collections.emptyList(), Collections.emptyList(), maxSizePercentage,
                    expireAfterAccessMinutes);
        }

        final Map<Boolean, List<AivenAcl>> partitionedEntries = aclEntries.stream()
                .collect(Collectors.partitioningBy(x -> x.getPermissionType() == AclPermissionType.DENY));
        return new VerdictCache(partitionedEntries.get(true), partitionedEntries.get(false), maxSizePercentage,
                expireAfterAccessMinutes);
    }
}
