/*
 * Copyright 2019 Aiven Oy https://aiven.io
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

import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import io.aiven.kafka.auth.json.AivenKafkaPrincipalMapping;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * The state for {@code PrincipalMappers}.
 *
 * <p>This was externalized into a class to allow the loaded principal mappers,
 * the "last modified" timestamp of the file they mappers were loaded from,
 * and the cache associated with this set of mappers to be treated atomically.
 * This helps to avoid some unpleasant concurrency effects on the cache without
 * excessive synchronization.
 */
class PrincipalMappersState {
    private static final FileTime LAST_MODIFIED_MIN = FileTime.fromMillis(-1);

    private final List<AivenKafkaPrincipalMapping> principalMappers;
    private final FileTime configLastModified;
    private final Cache<String, AivenKafkaPrincipalMapping> mappersCache;

    private PrincipalMappersState(final Collection<AivenKafkaPrincipalMapping> principalMappers,
                                  final FileTime configLastModified,
                                  final long cacheCapacity) {
        this.principalMappers = Collections.unmodifiableList(new ArrayList<>(principalMappers));
        this.configLastModified = configLastModified;
        this.mappersCache = CacheBuilder.newBuilder().maximumSize(cacheCapacity).build();
    }

    static PrincipalMappersState build(final Collection<AivenKafkaPrincipalMapping> principalMappers,
                                       final FileTime configLastModified,
                                       final long cacheCapacity) {
        return new PrincipalMappersState(principalMappers, configLastModified, cacheCapacity);
    }

    static PrincipalMappersState empty() {
        // This should always create a new empty state to keep its cache clean.
        return new PrincipalMappersState(Collections.emptyList(), LAST_MODIFIED_MIN, 0);
    }

    final List<AivenKafkaPrincipalMapping> getPrincipalMappers() {
        return principalMappers;
    }

    final FileTime getConfigLastModified() {
        return configLastModified;
    }

    final Cache<String, AivenKafkaPrincipalMapping> getMappersCache() {
        return mappersCache;
    }
}
