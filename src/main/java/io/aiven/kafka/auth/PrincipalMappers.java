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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.json.AivenKafkaPrincipalMapping;
import io.aiven.kafka.auth.json.reader.JsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;
import io.aiven.kafka.auth.json.reader.KafkaPrincipalJsonReader;
import io.aiven.kafka.auth.utils.TimeWithTimer;
import io.aiven.kafka.auth.utils.Timer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PrincipalMappers {
    private static final Logger LOGGER = LoggerFactory.getLogger(PrincipalMappers.class);

    private final File configFile;
    private final long refreshTimeoutMs;
    private final Timer refreshTimer;
    private final long cacheCapacity;

    private final JsonReader<AivenKafkaPrincipalMapping> jsonReader;

    // must be volatile to be safely readable without explicit synchronization
    private volatile PrincipalMappersState state = PrincipalMappersState.empty();

    PrincipalMappers(final String configFileLocation,
                     final long refreshTimeoutMs,
                     final TimeWithTimer time,
                     final long cacheCapacity) {
        this.configFile = new File(configFileLocation);
        this.refreshTimeoutMs = refreshTimeoutMs;
        this.refreshTimer = time.timer(0); // first update without a delay
        this.cacheCapacity = cacheCapacity;
        this.jsonReader = new KafkaPrincipalJsonReader(this.configFile.toPath());
    }

    KafkaPrincipal match(final String sslPrincipal) {
        final PrincipalMappersState state = getState();

        final AivenKafkaPrincipalMapping mapping = state.getMappersCache().getIfPresent(sslPrincipal);
        if (mapping != null) {
            return mapping.buildKafkaPrincipal(sslPrincipal);
        }

        for (final AivenKafkaPrincipalMapping mapper : state.getPrincipalMappers()) {
            if (mapper.matches(sslPrincipal)) {
                state.getMappersCache().put(sslPrincipal, mapper);
                return mapper.buildKafkaPrincipal(sslPrincipal);
            }
        }

        final AivenKafkaPrincipalMapping forUnknownPrincipal =
            AivenKafkaPrincipalMapping.forUnknownSslPrincipal();
        state.getMappersCache().put(sslPrincipal, forUnknownPrincipal);
        return forUnknownPrincipal.buildKafkaPrincipal(sslPrincipal);
    }

    /**
     * Get a valid state of principal mappers.
     *
     * <p>If the refresh timer has expired and there is a new config file, the new state will be
     * built, containing the principal matched loaded from the file and an empty cache.
     *
     * <p>The timer will be reset despite if the load happened or not.
     */
    private PrincipalMappersState getState() {
        refreshTimer.update();
        if (!refreshTimer.isExpired()) {
            return state;
        }

        // This block, the loading of the file and construction of a new state, is made synchronized
        // in the assumption that it might be called concurrently.
        synchronized (this) {
            try {
                final FileTime currentConfigLastModified = Files.getLastModifiedTime(configFile.toPath());
                final boolean reloadNeeded = !currentConfigLastModified.equals(state.getConfigLastModified());
                if (reloadNeeded) {
                    state = PrincipalMappersState.build(
                        jsonReader.read(),
                        currentConfigLastModified,
                        cacheCapacity);
                }
                // The timer must be reset despite if reload happened.
                refreshTimer.updateAndReset(refreshTimeoutMs);
                return state;
            } catch (final IOException | JsonReaderException ex) {
                LOGGER.error("Failed to read configuration file", ex);
                state = PrincipalMappersState.empty();
                refreshTimer.updateAndReset(0);
            }
            return state;
        }
    }

}
