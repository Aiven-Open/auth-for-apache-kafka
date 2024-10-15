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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.metrics.Sensor;

import io.aiven.kafka.auth.audit.NoAuditor;
import io.aiven.kafka.auth.audit.UserActivityAuditor;
import io.aiven.kafka.auth.audit.UserOperationsActivityAuditor;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AivenAclAuthorizerConfigTest {

    @Test
    void correctMinimalConfig() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.configuration", "/test");

        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(properties);
        assertEquals("/test", config.getConfigFile().getAbsolutePath());
        assertEquals(NoAuditor.class, config.getAuditor().getClass());
        assertTrue(config.logDenials());
        assertTrue(config.listAclsEnabled());
        // metric configs
        assertThat(config.getLong(AivenAclAuthorizerConfig.METRICS_SAMPLE_WINDOW_MS_CONFIG))
            .isEqualTo(30_000);
        assertThat(config.getInt(AivenAclAuthorizerConfig.METRICS_NUM_SAMPLES_CONFIG))
            .isEqualTo(2);
        assertThat(config.getString(AivenAclAuthorizerConfig.METRICS_RECORDING_LEVEL_CONFIG))
            .isEqualTo(Sensor.RecordingLevel.INFO.name());
    }

    @Test
    void correctFullConfig() {
        final Map<String, String> userActivityProps = new HashMap<>();
        userActivityProps.put("aiven.acl.authorizer.configuration", "/test");
        userActivityProps.put("aiven.acl.authorizer.auditor.class.name", UserActivityAuditor.class.getName());
        userActivityProps.put("aiven.acl.authorizer.auditor.aggregation.period", "123");
        userActivityProps.put("aiven.acl.authorizer.log.denials", "false");
        userActivityProps.put("aiven.acl.authorizer.config.refresh.interval", "10");
        userActivityProps.put("aiven.acl.authorizer.list.acls.enabled", "false");
        userActivityProps.put("aiven.acl.authorizer.metrics.sample.window.ms", "10000");
        userActivityProps.put("aiven.acl.authorizer.metrics.num.samples", "10");
        userActivityProps.put("aiven.acl.authorizer.metrics.recording.level", "DEBUG");

        var config = new AivenAclAuthorizerConfig(userActivityProps);
        assertEquals("/test", config.getConfigFile().getAbsolutePath());
        assertEquals(UserActivityAuditor.class, config.getAuditor().getClass());
        assertFalse(config.logDenials());
        assertEquals(10, config.configRefreshInterval());
        assertFalse(config.listAclsEnabled());
        // metrics
        assertThat(config.getLong(AivenAclAuthorizerConfig.METRICS_SAMPLE_WINDOW_MS_CONFIG))
            .isEqualTo(10_000);
        assertThat(config.getInt(AivenAclAuthorizerConfig.METRICS_NUM_SAMPLES_CONFIG))
            .isEqualTo(10);
        assertThat(config.getString(AivenAclAuthorizerConfig.METRICS_RECORDING_LEVEL_CONFIG))
            .isEqualTo(Sensor.RecordingLevel.DEBUG.name());

        final Map<String, String> userActivityOpsProps = new HashMap<>();
        userActivityOpsProps.put("aiven.acl.authorizer.configuration", "/test");
        userActivityOpsProps.put("aiven.acl.authorizer.auditor.class.name",
                UserOperationsActivityAuditor.class.getName());
        userActivityOpsProps.put("aiven.acl.authorizer.auditor.aggregation.period", "123");
        userActivityOpsProps.put("aiven.acl.authorizer.log.denials", "false");
        userActivityOpsProps.put("aiven.acl.authorizer.config.refresh.interval", "10");

        config = new AivenAclAuthorizerConfig(userActivityOpsProps);
        assertEquals("/test", config.getConfigFile().getAbsolutePath());
        assertEquals(UserOperationsActivityAuditor.class, config.getAuditor().getClass());
        assertFalse(config.logDenials());
        assertEquals(10, config.configRefreshInterval());
    }

    @Test
    void missingConfigPath() {
        final Map<String, String> properties = new HashMap<>();

        final Throwable t = assertThrows(
            ConfigException.class,
            () -> new AivenAclAuthorizerConfig(properties));
        assertEquals(
            "Missing required configuration \"aiven.acl.authorizer.configuration\" which has no default value.",
            t.getMessage()
        );
    }

    @Test
    void incorrectAuditorClass() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.configuration", "/test");
        properties.put("aiven.acl.authorizer.auditor.class.name", ArrayList.class.getName());

        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(properties);
        final Throwable t = assertThrows(
            KafkaException.class,
            config::getAuditor);
        assertEquals(
            "class java.util.ArrayList is not an instance of io.aiven.kafka.auth.audit.AuditorAPI",
            t.getMessage()
        );
    }
}
