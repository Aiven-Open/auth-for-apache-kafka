/*
 * Copyright 2020 Aiven Oy https://aiven.io
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

import java.util.Map;

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigDef;

import static io.aiven.kafka.auth.audit.AuditorConfig.AggregationGrouping.USER;
import static io.aiven.kafka.auth.audit.AuditorConfig.AggregationGrouping.USER_AND_IP;

public class AuditorConfig extends AbstractConfig {

    static final String AGGREGATION_PERIOD_CONF = "aiven.acl.authorizer.auditor.aggregation.period";
    static final String AGGREGATION_GROUPING_CONF = "aiven.acl.authorizer.auditor.aggregation.grouping";

    public enum AggregationGrouping {
        USER("user"),
        USER_AND_IP("user_and_ip");

        private final String configValue;

        AggregationGrouping(final String configValue) {
            this.configValue = configValue;
        }

        public String getConfigValue() {
            return configValue;
        }

        public static AggregationGrouping fromConfigValue(final String configValue) {
            for (final var ag : values()) {
                if (ag.configValue.equals(configValue)) {
                    return ag;
                }
            }
            throw new IllegalArgumentException("Unsupported aggregation grouping: " + configValue);
        }

    }

    public AuditorConfig(final Map<?, ?> originals) {
        super(configDef(), originals);
    }

    public static ConfigDef configDef() {
        return new ConfigDef()
            .define(
                AGGREGATION_PERIOD_CONF,
                ConfigDef.Type.LONG,
                ConfigDef.NO_DEFAULT_VALUE,
                ConfigDef.Range.atLeast(1),
                ConfigDef.Importance.HIGH,
                "The auditor aggregation period in seconds."
            ).define(
                AGGREGATION_GROUPING_CONF,
                ConfigDef.Type.STRING,
                USER_AND_IP.getConfigValue(),
                ConfigDef.ValidString.in(USER.getConfigValue(),
                        USER_AND_IP.getConfigValue()),
                ConfigDef.Importance.HIGH,
                "The auditor aggregation grouping key."
            );
    }

    public long getAggregationPeriodInSeconds() {
        return getLong(AGGREGATION_PERIOD_CONF);
    }

    public AggregationGrouping getAggregationGrouping() {
        return AggregationGrouping.fromConfigValue(getString(AGGREGATION_GROUPING_CONF));
    }
}
