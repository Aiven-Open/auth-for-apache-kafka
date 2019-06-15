package io.aiven.kafka.auth;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

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

  private final List<AivenKafkaPrincipalMappingEntry> principalMappers;
  private final FileTime configLastModified;
  private final Cache<String, AivenKafkaPrincipalMappingEntry> mappersCache;

  private PrincipalMappersState(Collection<AivenKafkaPrincipalMappingEntry> principalMappers,
                                FileTime configLastModified,
                                long cacheCapacity) {
    this.principalMappers = Collections.unmodifiableList(new ArrayList<>(principalMappers));
    this.configLastModified = configLastModified;
    this.mappersCache = CacheBuilder.newBuilder().maximumSize(cacheCapacity).build();
  }

  final List<AivenKafkaPrincipalMappingEntry> getPrincipalMappers() {
    return principalMappers;
  }

  final FileTime getConfigLastModified() {
    return configLastModified;
  }

  final Cache<String, AivenKafkaPrincipalMappingEntry> getMappersCache() {
    return mappersCache;
  }

  static PrincipalMappersState build(Collection<AivenKafkaPrincipalMappingEntry> principalMappers,
                                     FileTime configLastModified,
                                     long cacheCapacity) {
    return new PrincipalMappersState(principalMappers, configLastModified, cacheCapacity);
  }

  static PrincipalMappersState empty() {
    // This should always create a new empty state to keep its cache clean.
    return new PrincipalMappersState(Collections.emptyList(), LAST_MODIFIED_MIN, 0);
  }
}
