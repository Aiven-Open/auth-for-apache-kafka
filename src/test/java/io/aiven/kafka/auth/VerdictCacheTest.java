/*
 * Copyright 2025 Aiven Oy https://aiven.io
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

import java.util.Collections;
import java.util.UUID;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.json.AivenAcl;
import io.aiven.kafka.auth.utils.ObjectSizeEstimator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.openjdk.jol.info.GraphLayout;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VerdictCacheTest {

    @ParameterizedTest
    @ValueSource(strings = { "a", "Hello, World!", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "1234567890", "[]{}|;:'\"<>,./?`~!@#$%^&*()_+-=\\|" })
    void testStringSizeEstimation(final String s) throws Exception {
        final GraphLayout layout = GraphLayout.parseInstance(s);
        final long size = layout.totalSize();
        final long estimatedSize = ObjectSizeEstimator.estimateStringSize(s);
        assertEquals(size, estimatedSize);
    }

    @Test
    void testBooleanSizeEstimation() throws Exception {
        final Boolean testBoolean = true;
        final GraphLayout layout = GraphLayout.parseInstance(testBoolean);
        final long size = layout.totalSize();
        final long estimatedSize = ObjectSizeEstimator.estimateBooleanSize(testBoolean);
        assertEquals(size, estimatedSize);
    }

    @ParameterizedTest
    @CsvSource({
        "25, 33",
        "50, 20",
        "100, 10",
        "200, 10",
    })
    void testCacheEvictionBySize(final int sizeMB, final int errorTolerance) throws Exception {
        final long maxHeapSize = Runtime.getRuntime().maxMemory();

        final long cacheSizeBytes = sizeMB * 1024 * 1024;
        final double cacheSizePercentage = ((double) cacheSizeBytes / maxHeapSize) * 100;

        final VerdictCache cache = VerdictCache.create(
            Collections.singletonList(
                new AivenAcl("User", "^(.*)$", "10.0.0.1", "^(.*)$",
                    "^Topic:(.*)$", null, null, null, null, false)),
            cacheSizePercentage, 60);

        final KafkaPrincipal principal = new KafkaPrincipal("User", "testUser");
        final AclOperation operation = AclOperation.READ;
        final String resource = "testResource";

        long count = 0;
        while (true) {
            final String host = UUID.randomUUID().toString();
            cache.get(principal, host, operation, resource);
            count++;
            if (cache.getEstimatedSizeBytes() >= cacheSizeBytes * 0.99) {
                break;
            }
        }

        var layout = GraphLayout.parseInstance(cache);
        long size = layout.totalSize();
        long estimatedSize = cache.getEstimatedSizeBytes();
        double percentDifferenceEstimatedVsMeasured = ((double) Math.abs(size - estimatedSize) / estimatedSize) * 100;

        // Allow margin of error. Error is greatest when the cache is small.
        assertEquals(0, percentDifferenceEstimatedVsMeasured, errorTolerance);

        // Add 100% more entries to the cache to see if it will evict entries based on size
        for (var i = 0; i < count; i++) {
            final String host = UUID.randomUUID().toString();
            cache.get(principal, host, operation, resource);
        }

        layout = GraphLayout.parseInstance(cache);
        size = layout.totalSize();
        estimatedSize = cache.getEstimatedSizeBytes();
        percentDifferenceEstimatedVsMeasured = ((double) Math.abs(size - estimatedSize) / estimatedSize) * 100;

        // Allow margin of error. Error is greatest when the cache is small.
        assertEquals(0, percentDifferenceEstimatedVsMeasured, errorTolerance);

        // Check difference between desired size and measured size
        final double percentDifferenceDesiredVsMeasured = 
            ((double) Math.abs(cacheSizeBytes - estimatedSize) / estimatedSize) * 100;
        
        assertEquals(0, percentDifferenceDesiredVsMeasured, errorTolerance);
    }

}
