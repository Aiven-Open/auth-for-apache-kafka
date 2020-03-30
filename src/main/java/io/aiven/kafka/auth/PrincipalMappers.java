/**
 * Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.utils.TimeWithTimer;
import io.aiven.kafka.auth.utils.Timer;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PrincipalMappers {
    private static final Logger LOGGER = LoggerFactory.getLogger(AivenKafkaPrincipalBuilder.class);

    private final File configFile;
    private final long refrestTimeoutMs;
    private final Timer refreshTimer;
    private final long cacheCapacity;

    // must be volatile to be safely readable without explicit synchronization
    private volatile PrincipalMappersState state = PrincipalMappersState.empty();

    PrincipalMappers(final String configFileLocation,
                     final long refreshTimeoutMs,
                     final TimeWithTimer time,
                     final long cacheCapacity) {
        this.configFile = new File(configFileLocation);
        this.refrestTimeoutMs = refreshTimeoutMs;
        this.refreshTimer = time.timer(0); // first update without a delay
        this.cacheCapacity = cacheCapacity;
    }

    KafkaPrincipal match(final String sslPrincipal) {
        final PrincipalMappersState state = getState();

        final AivenKafkaPrincipalMappingEntry mapping = state.getMappersCache().getIfPresent(sslPrincipal);
        if (mapping != null) {
            return mapping.buildKafkaPrincipal(sslPrincipal);
        }

        for (final AivenKafkaPrincipalMappingEntry mapper : state.getPrincipalMappers()) {
            if (mapper.matches(sslPrincipal)) {
                state.getMappersCache().put(sslPrincipal, mapper);
                return mapper.buildKafkaPrincipal(sslPrincipal);
            }
        }

        final AivenKafkaPrincipalMappingEntry forUnknownPrincipal =
            AivenKafkaPrincipalMappingEntry.forUnknownSslPrincipal();
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
                        loadPrincipalMappers(),
                        currentConfigLastModified,
                        cacheCapacity);
                }
                // The timer must be reset despite if reload happened.
                refreshTimer.updateAndReset(refrestTimeoutMs);
                return state;
            } catch (final IOException | ParseException ex) {
                LOGGER.error("Failed to read configuration file", ex);
                state = PrincipalMappersState.empty();
                refreshTimer.updateAndReset(0);
            }
            return state;
        }
    }

    private List<AivenKafkaPrincipalMappingEntry> loadPrincipalMappers()
        throws IOException, ParseException {
        try (final Reader reader = new BufferedReader(new FileReader(configFile))) {
            final JSONArray rootArray = (JSONArray) new JSONParser().parse(reader);
            final List<AivenKafkaPrincipalMappingEntry> newPrincipalMappers =
                new ArrayList<>(rootArray.size());
            for (final Object itemObj : rootArray) {
                final JSONObject item = (JSONObject) itemObj;
                final AivenKafkaPrincipalMappingEntry principalMapper =
                    new AivenKafkaPrincipalMappingEntry(
                        (String) item.get("subject_matcher"),
                        (String) item.get("principal_name"),
                        (String) item.get("principal_type")
                    );
                newPrincipalMappers.add(principalMapper);
            }
            return newPrincipalMappers;
        }
    }
}
