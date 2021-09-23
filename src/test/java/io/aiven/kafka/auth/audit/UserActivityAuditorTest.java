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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import kafka.network.RequestChannel.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserActivityAuditorTest {

    @Mock
    private Logger logger;

    private Session session;
    private AclOperation operation;
    private ResourcePattern resource;

    @BeforeEach
    void setUp() throws Exception {
        final KafkaPrincipal principal =
                new KafkaPrincipal("PRINCIPAL_TYPE", "PRINCIPAL_NAME");
        session = new Session(principal, InetAddress.getLocalHost());
        resource =
            new ResourcePattern(
                ResourceType.CLUSTER,
                "resource",
                PatternType.LITERAL
            );
        operation = AclOperation.ALTER;
    }

    @Test
    public void shouldDumpMessagesWhenStop() {
        final UserActivityAuditor auditor = spy(createAuditor());
        auditor.addActivity(session, operation, resource, false);
        auditor.stop();
        verify(auditor).dump();
    }

    @Test
    public void shouldBuildRightLogMessage() throws UnknownHostException {
        final Auditor auditor = createAuditor();

        auditor.addActivity(session, operation, resource, false);
        assertEquals(1, auditor.auditStorage.size());
        auditor.dump();
        assertEquals(0, auditor.auditStorage.size());

        final ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(logger).info(argument.capture());

        final String expectedPrefix = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME (%s) was active since ",
                InetAddress.getLocalHost()
        );
        assertTrue(argument.getValue().startsWith(expectedPrefix));

        final String timestampStr = argument.getValue().substring(expectedPrefix.length());
        final Instant instant = Instant.parse(timestampStr);
        final long diffSeconds = Math.abs(ChronoUnit.SECONDS.between(instant, Instant.now()));
        assertTrue(diffSeconds < 3);
    }

    @Test
    void shouldThrowConfigExceptionForAggregationGrouping() {

        final var props = Map.of(
                AuditorConfig.AGGREGATION_PERIOD_CONF, Long.MAX_VALUE,
                AuditorConfig.AGGREGATION_GROUPING_CONF, AuditorConfig.AggregationGrouping.USER.getConfigValue()
        );
        final var e = assertThrows(
                ConfigException.class, () -> createAuditor(props));
        assertEquals("Grouping by user is not supported for this type of auditor", e.getMessage());
    }

    private UserActivityAuditor createAuditor() {
        return createAuditor(Map.of(AuditorConfig.AGGREGATION_PERIOD_CONF, Long.MAX_VALUE));
    }

    private UserActivityAuditor createAuditor(final Map<String, ?> props) {
        final UserActivityAuditor auditor = new UserActivityAuditor(logger);
        auditor.configure(props);
        return auditor;
    }
}
