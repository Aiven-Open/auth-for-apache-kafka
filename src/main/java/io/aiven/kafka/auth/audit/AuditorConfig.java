/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.util.Map;

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigDef;

public class AuditorConfig extends AbstractConfig {

    static final String AGGREGATION_PERIOD_CONF = "aiven.acl.authorizer.auditor.aggregation.period";

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
            );
    }

    public long getAggregationPeriodInSeconds() {
        return getLong(AGGREGATION_PERIOD_CONF);
    }
}
