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

import java.util.List;

import org.apache.kafka.common.MetricNameTemplate;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.metrics.JmxReporter;
import org.apache.kafka.common.metrics.KafkaMetricsContext;
import org.apache.kafka.common.metrics.MetricConfig;
import org.apache.kafka.common.metrics.Metrics;
import org.apache.kafka.common.metrics.Sensor;
import org.apache.kafka.common.metrics.Sensor.RecordingLevel;
import org.apache.kafka.common.metrics.stats.CumulativeCount;
import org.apache.kafka.common.metrics.stats.Rate;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.utils.Time;
import org.apache.kafka.server.authorizer.AuthorizationResult;

public class AivenAclAuthorizerMetrics {
    static final String METRIC_GROUP_NAME = "auth-metrics";
    static final String AUTH_OP_ALLOW = "auth-ops-allow";
    static final String AUTH_OP_ALLOW_DESC = "successful authorizer operations allowed based on ACLs";
    static final String AUTH_OP_ALLOW_RATE = AUTH_OP_ALLOW + "-rate";
    static final String AUTH_OP_ALLOW_TOTAL = AUTH_OP_ALLOW + "-total";
    final MetricNameTemplate authOpAllowRate = new MetricNameTemplate(
        AUTH_OP_ALLOW_RATE,
        METRIC_GROUP_NAME,
        "Rate of " + AUTH_OP_ALLOW_DESC
    );
    final MetricNameTemplate authOpAllowRateByOperation = new MetricNameTemplate(
        AUTH_OP_ALLOW_RATE,
        METRIC_GROUP_NAME,
        "Rate of " + AUTH_OP_ALLOW_DESC + " tagged by operation type",
        "operation"
    );
    final MetricNameTemplate authOpAllowTotal = new MetricNameTemplate(
        AUTH_OP_ALLOW_TOTAL,
        METRIC_GROUP_NAME,
        "Total number of " + AUTH_OP_ALLOW_DESC
    );
    final MetricNameTemplate authOpAllowTotalByOperation = new MetricNameTemplate(
        AUTH_OP_ALLOW_TOTAL,
        METRIC_GROUP_NAME,
        "Total number of " + AUTH_OP_ALLOW_DESC + " tagged by operation type",
        "operation"
    );
    static final String AUTH_OP_DENY = "auth-ops-deny";
    static final String AUTH_OP_DENY_DESC = "authorizer operations denied/blocked based on ACLs";
    static final String AUTH_OP_DENY_RATE = AUTH_OP_DENY + "-rate";
    static final String AUTH_OP_DENY_TOTAL = AUTH_OP_DENY + "-total";
    final MetricNameTemplate authOpDenyRate = new MetricNameTemplate(
        AUTH_OP_DENY_RATE,
        METRIC_GROUP_NAME,
        "Rate of " + AUTH_OP_DENY_DESC
    );
    final MetricNameTemplate authOpDenyRateByOperationResourcePrincipal = new MetricNameTemplate(
        AUTH_OP_DENY_RATE,
        METRIC_GROUP_NAME,
        "Rate of " + AUTH_OP_DENY_DESC + " tagged by operation type, resource name, and principal name",
        "operation",
        "resource",
        "principal"
    );
    final MetricNameTemplate authOpDenyTotal = new MetricNameTemplate(
        AUTH_OP_DENY_TOTAL,
        METRIC_GROUP_NAME,
        "Total number of " + AUTH_OP_DENY_DESC
    );
    final MetricNameTemplate authOpDenyTotalByOperationResourcePrincipal = new MetricNameTemplate(
        AUTH_OP_DENY_TOTAL, 
        METRIC_GROUP_NAME,
        "Total number of " + AUTH_OP_DENY_DESC + " tagged by operation type, resource name, and principal name",
        "operation",
        "resource",
        "principal"
    );

    final Metrics metrics;
    final Sensor authOpAllowSensor;
    final Sensor authOpDenySensor;

    public AivenAclAuthorizerMetrics(final Time time, final MetricConfig metricConfig) {
        final JmxReporter reporter = new JmxReporter();
        
        this.metrics = new Metrics(
            metricConfig,
            List.of(reporter),
            time,
            new KafkaMetricsContext("aiven.kafka.auth")
        );

        authOpAllowSensor = metrics.sensor(AUTH_OP_ALLOW, RecordingLevel.INFO);
        authOpAllowSensor.add(metrics.metricInstance(authOpAllowRate), new Rate());
        authOpAllowSensor.add(metrics.metricInstance(authOpAllowTotal), new CumulativeCount());
        authOpDenySensor = metrics.sensor(AUTH_OP_DENY, RecordingLevel.INFO);
        authOpDenySensor.add(metrics.metricInstance(authOpDenyRate), new Rate());
        authOpDenySensor.add(metrics.metricInstance(authOpDenyTotal), new CumulativeCount());
    }

    public void recordLogAuthResult(
        final AuthorizationResult result,
        final AclOperation operation,
        final ResourcePattern resourcePattern,
        final KafkaPrincipal principal
    ) {
        switch (result) {
            case ALLOWED: {
                final String sensorName = AUTH_OP_ALLOW + "," + operation.name();
                Sensor s = metrics.getSensor(sensorName);
                if (s == null) {
                    s = metrics.sensor(sensorName, RecordingLevel.INFO, authOpAllowSensor);
                    s.add(
                            metrics.metricInstance(
                                    authOpAllowRateByOperation,
                                    "operation", operation.name()),
                            new Rate());
                    s.add(
                            metrics.metricInstance(
                                    authOpAllowTotalByOperation,
                                    "operation", operation.name()),
                            new CumulativeCount());
                }
                s.record();
                break;
            }
            case DENIED: {
                final String sensorName = AUTH_OP_DENY + "," + operation.name() + ","
                        + resourcePattern.name() + "," + principal.getName();
                Sensor s = metrics.getSensor(sensorName);
                if (s == null) {
                    s = metrics.sensor(sensorName, RecordingLevel.INFO, authOpDenySensor);
                    s.add(
                            metrics.metricInstance(
                                    authOpDenyRateByOperationResourcePrincipal,
                                    "operation", operation.name(),
                                    "resource", EscapeTagValue.apply(resourcePattern.name()),
                                    "principal", EscapeTagValue.apply(principal.getName())),
                            new Rate());
                    s.add(
                            metrics.metricInstance(
                                    authOpDenyTotalByOperationResourcePrincipal,
                                    "operation", operation.name(),
                                    "resource", EscapeTagValue.apply(resourcePattern.name()),
                                    "principal", EscapeTagValue.apply(principal.getName())),
                            new CumulativeCount());
                }
                s.record();
                break;
            }
            default: break;
        }
    }
}
