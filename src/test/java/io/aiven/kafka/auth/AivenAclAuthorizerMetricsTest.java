/*
 * Copyright 2024 Aiven Oy https://aiven.io
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

import javax.management.MBeanServer;
import javax.management.ObjectName;

import java.lang.management.ManagementFactory;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.metrics.MetricConfig;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.server.authorizer.AuthorizationResult;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AivenAclAuthorizerMetricsTest {

    private static final MBeanServer MBEAN_SERVER = ManagementFactory.getPlatformMBeanServer();

    @Test
    void recordMetrics() throws Exception {
        final var metrics = new AivenAclAuthorizerMetrics(Time.SYSTEM, new MetricConfig());

        final var name = "aiven.kafka.auth:type=auth-metrics";
        final var metricMBean = new ObjectName(name);
        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-allow-total"))
            .isEqualTo(0.0);
        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-deny-total"))
            .isEqualTo(0.0);

        metrics.recordLogAuthResult(
            AuthorizationResult.ALLOWED,
            AclOperation.ALTER,
            new ResourcePattern(ResourceType.TOPIC, "t1", PatternType.LITERAL),
            new KafkaPrincipal("USER", "u1"));

        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-allow-total"))
            .isEqualTo(1.0);
        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-deny-total"))
            .isEqualTo(0.0);

        {
            final var allowedByOpMBean = new ObjectName(name + ",operation=" + AclOperation.ALTER);
            assertThat(MBEAN_SERVER.getAttribute(allowedByOpMBean, "auth-ops-allow-total"))
                .isEqualTo(1.0);
        }

        metrics.recordLogAuthResult(
            AuthorizationResult.DENIED,
            AclOperation.WRITE,
            new ResourcePattern(ResourceType.TOPIC, "t1", PatternType.LITERAL),
            new KafkaPrincipal("USER", "u1"));

        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-allow-total"))
            .isEqualTo(1.0);
        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-deny-total"))
            .isEqualTo(1.0);

        {
            final var deniedByOpMBean = new ObjectName(name + ",operation=" + AclOperation.WRITE
                + ",resource=t1,principal=u1");
            assertThat(MBEAN_SERVER.getAttribute(deniedByOpMBean, "auth-ops-deny-total"))
                .isEqualTo(1.0);
        }

        metrics.recordLogAuthResult(
            AuthorizationResult.DENIED,
            AclOperation.WRITE,
            new ResourcePattern(ResourceType.TOPIC, "t2", PatternType.LITERAL),
            new KafkaPrincipal("USER", "u2"));

        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-allow-total"))
            .isEqualTo(1.0);
        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-deny-total"))
            .isEqualTo(2.0);

        {
            final var deniedByOpMBean = new ObjectName(name + ",operation=" + AclOperation.WRITE
                + ",resource=t2,principal=u2");
            assertThat(MBEAN_SERVER.getAttribute(deniedByOpMBean, "auth-ops-deny-total"))
                .isEqualTo(1.0);
        }

        for (int i = 0; i < 10; i++) {
            metrics.recordLogAuthResult(
                AuthorizationResult.ALLOWED,
                AclOperation.WRITE,
                new ResourcePattern(ResourceType.TOPIC, "t2", PatternType.LITERAL),
                new KafkaPrincipal("USER", "u2"));
        }

        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-allow-total"))
            .isEqualTo(11.0);
        assertThat(MBEAN_SERVER.getAttribute(metricMBean, "auth-ops-deny-total"))
            .isEqualTo(2.0);

        {
            final var allowedByOpMBean = new ObjectName(name + ",operation=" + AclOperation.WRITE);
            assertThat(MBEAN_SERVER.getAttribute(allowedByOpMBean, "auth-ops-allow-total"))
                .isEqualTo(10.0);
        }
    }
}
