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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.json.AivenAcl;

public class VerdictCache {
    private final List<AivenAcl> aclEntries;
    private final Map<String, Boolean> cache = new ConcurrentHashMap<>();

    private VerdictCache(final List<AivenAcl> aclEntries) {
        this.aclEntries = aclEntries;
    }

    public boolean get(final KafkaPrincipal principal,
                       final String operation,
                       final String resource) {
        if (aclEntries != null) {
            final String cacheKey = resource
                + "|" + operation
                + "|" + principal.getName()
                + "|" + principal.getPrincipalType();

            final Predicate<AivenAcl> matcher = aclEntry ->
                aclEntry.check(principal.getPrincipalType(), principal.getName(), operation, resource);
            return cache.computeIfAbsent(cacheKey, key -> aclEntries.stream().anyMatch(matcher));
        } else {
            return false;
        }
    }

    public static VerdictCache create(final List<AivenAcl> aclEntries) {
        return new VerdictCache(aclEntries);
    }
}
