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
import java.util.Map;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.metrics.Sensor;

import io.aiven.kafka.auth.audit.AuditorAPI;
import io.aiven.kafka.auth.audit.NoAuditor;

import static org.apache.kafka.common.config.ConfigDef.Range.atLeast;
import static org.apache.kafka.common.config.ConfigDef.ValidString.in;

public final class AivenAclAuthorizerConfig extends AbstractConfig {
    public static final String PREFIX = "aiven.acl.authorizer.";
    private static final String CONFIGURATION_CONF = PREFIX + "configuration";
    private static final String AUDITOR_CLASS_NAME_CONF = PREFIX + "auditor.class.name";
    private static final String LOG_DENIALS_CONF = PREFIX + "log.denials";
    private static final String CONFIG_REFRESH_CONF = PREFIX + "config.refresh.interval";
    private static final String LIST_ACLS_ENABLED_CONF = PREFIX + "list.acls.enabled";


    public static final String METRICS_NUM_SAMPLES_CONFIG = PREFIX
        + CommonClientConfigs.METRICS_NUM_SAMPLES_CONFIG;
    private static final String METRICS_NUM_SAMPLES_DOC = CommonClientConfigs.METRICS_NUM_SAMPLES_DOC;

    public static final String METRICS_SAMPLE_WINDOW_MS_CONFIG = PREFIX
        + CommonClientConfigs.METRICS_SAMPLE_WINDOW_MS_CONFIG;
    private static final String METRICS_SAMPLE_WINDOW_MS_DOC = CommonClientConfigs.METRICS_SAMPLE_WINDOW_MS_DOC;

    public static final String METRICS_RECORDING_LEVEL_CONFIG = PREFIX
        + CommonClientConfigs.METRICS_RECORDING_LEVEL_CONFIG;
    private static final String METRICS_RECORDING_LEVEL_DOC = CommonClientConfigs.METRICS_RECORDING_LEVEL_DOC;

    public AivenAclAuthorizerConfig(final Map<?, ?> originals) {
        super(configDef(), originals);
    }

    public static ConfigDef configDef() {
        return new ConfigDef()
            .define(
                CONFIGURATION_CONF,
                ConfigDef.Type.STRING,
                ConfigDef.NO_DEFAULT_VALUE,
                ConfigDef.Importance.HIGH,
                "The path to the configuration file"
            )
            .define(
                AUDITOR_CLASS_NAME_CONF,
                ConfigDef.Type.CLASS,
                NoAuditor.class,
                ConfigDef.Importance.MEDIUM,
                "The auditor class fully qualified name"
            )
            .define(
                LOG_DENIALS_CONF,
                ConfigDef.Type.BOOLEAN,
                true,
                ConfigDef.Importance.LOW,
                "Whether to log denials on INFO level"
            )
            .define(
                CONFIG_REFRESH_CONF,
                ConfigDef.Type.INT,
                10_000,
                ConfigDef.Importance.LOW,
                "The interval between ACL reloads"
            )
            .define(
                LIST_ACLS_ENABLED_CONF,
                ConfigDef.Type.BOOLEAN,
                true,
                ConfigDef.Importance.LOW,
                "Whether to allow listing ACLs"
            )
            // metric configs
            .define(
                METRICS_SAMPLE_WINDOW_MS_CONFIG,
                ConfigDef.Type.LONG,
                30000,
                atLeast(1),
                ConfigDef.Importance.LOW,
                METRICS_SAMPLE_WINDOW_MS_DOC
            )
            .define(
                METRICS_NUM_SAMPLES_CONFIG,
                ConfigDef.Type.INT,
                2,
                atLeast(1),
                ConfigDef.Importance.LOW,
                METRICS_NUM_SAMPLES_DOC
            )
            .define(
                METRICS_RECORDING_LEVEL_CONFIG,
                ConfigDef.Type.STRING,
                Sensor.RecordingLevel.INFO.toString(),
                in(Sensor.RecordingLevel.INFO.toString(),
                    Sensor.RecordingLevel.DEBUG.toString(),
                    Sensor.RecordingLevel.TRACE.toString()),
                ConfigDef.Importance.LOW,
                METRICS_RECORDING_LEVEL_DOC
            );
    }

    public File getConfigFile() {
        return new File(getString(CONFIGURATION_CONF));
    }

    public AuditorAPI getAuditor() {
        return getConfiguredInstance(AUDITOR_CLASS_NAME_CONF, AuditorAPI.class);
    }

    public boolean logDenials() {
        return getBoolean(LOG_DENIALS_CONF);
    }

    public int configRefreshInterval() {
        return getInt(CONFIG_REFRESH_CONF);
    }

    public boolean listAclsEnabled() {
        return getBoolean(LIST_ACLS_ENABLED_CONF);
    }
}
