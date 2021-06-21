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
        assertEquals(AuditorConfig.AggregationGrouping.USER_AND_IP,
                config.getAggregationGrouping());
    }

    @Test
    void correctFullConfig() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.auditor.aggregation.period", "123");
        properties.put("aiven.acl.authorizer.auditor.aggregation.grouping", "user");

        final AuditorConfig config = new AuditorConfig(properties);
        assertEquals(123, config.getAggregationPeriodInSeconds());
        assertEquals(AuditorConfig.AggregationGrouping.USER,
                config.getAggregationGrouping());
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
