/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.common.config.ConfigException;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuditorConfigTest {
    @Test
    void correctMinimalConfig() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.auditor.aggregation.period", "123");

        final AuditorConfig config = new AuditorConfig(properties);
        assertEquals(123, config.getAggregationPeriodInSeconds());
    }

    @Test
    void missingAggregationPeriod() {
        final Map<String, String> properties = new HashMap<>();

        final Throwable t = assertThrows(
            ConfigException.class,
            () -> new AuditorConfig(properties));
        assertEquals(
            "Missing required configuration \"aiven.acl.authorizer.auditor.aggregation.period\" "
                + "which has no default value.",
            t.getMessage()
        );
    }

    @Test
    void incorrectAggregationPeriod() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.auditor.aggregation.period", "-1");

        final Throwable t = assertThrows(
            ConfigException.class,
            () -> new AuditorConfig(properties));
        assertEquals(
            "Invalid value -1 for configuration aiven.acl.authorizer.auditor.aggregation.period: "
                + "Value must be at least 1",
            t.getMessage()
        );
    }
}
