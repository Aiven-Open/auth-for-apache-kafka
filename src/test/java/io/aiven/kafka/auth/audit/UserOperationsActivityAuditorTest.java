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
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserOperationsActivityAuditorTest {

    @Mock
    private Logger logger;

    private Session session;

    private KafkaPrincipal principal;

    private AclOperation operation;

    private ResourcePattern resource;

    @BeforeEach
    void setUp() throws Exception {
        principal = new KafkaPrincipal("PRINCIPAL_TYPE", "PRINCIPAL_NAME");
        session = new Session(principal, InetAddress.getLocalHost());

        operation = AclOperation.ALL;
        resource =
                new ResourcePattern(
                        ResourceType.CLUSTER,
                        "RESOURCE_NAME",
                        PatternType.LITERAL
                );
    }

    @Test
    public void shouldDumpMessagesWhenStop() {
        final UserOperationsActivityAuditor auditor = spy(createAuditor());
        auditor.addActivity(session, operation, resource, false);
        auditor.stop();
        verify(auditor).dump();
    }

    @Test
    public void shouldAddUserActivityAndOperation() throws UnknownHostException {
        final UserOperationsActivityAuditor auditor = createAuditor();

        auditor.addActivity(session, operation, resource, false);
        assertEquals(1, auditor.auditStorage.size());
        assertEquals(
                1,
                cast(auditor.auditStorage.get(
                        new Auditor.AuditKey(principal, InetAddress.getLocalHost())
                ), UserActivity.UserActivityOperations.class).operations.size()
        );
        auditor.dump();
        assertEquals(0, auditor.auditStorage.size());
    }

    @Test
    void shouldAggregateOperationsForSameUser() throws Exception {

        final Session anotherSession =
                new Session(principal, InetAddress.getByName("127.0.0.2"));

        final UserOperationsActivityAuditor auditor = createAuditor();

        auditor.addActivity(session, operation, resource, false);
        auditor.addActivity(session, operation, resource, true);
        auditor.addActivity(anotherSession, operation, resource, true);
        assertEquals(2, auditor.auditStorage.size());
        assertEquals(
                2,
                cast(auditor.auditStorage.get(
                        new Auditor.AuditKey(
                                session.getPrincipal(),
                                session.getClientAddress())
                ), UserActivity.UserActivityOperations.class).operations.size()
        );
        assertEquals(
                1,
                cast(auditor.auditStorage.get(
                        new Auditor.AuditKey(
                                anotherSession.getPrincipal(),
                                anotherSession.getClientAddress())
                ), UserActivity.UserActivityOperations.class).operations.size()
        );
        auditor.dump();
        assertEquals(0, auditor.auditStorage.size());
    }

    @Test
    void shouldAggregateOperationsForSameUserAndPrincipalGrouping() throws Exception {

        final Session anotherSession =
                new Session(principal, InetAddress.getByName("127.0.0.2"));

        final UserOperationsActivityAuditor auditor =
                createAuditor(Map.of(
                        AuditorConfig.AGGREGATION_PERIOD_CONF,
                        10L,
                        AuditorConfig.AGGREGATION_GROUPING_CONF,
                        AuditorConfig.AggregationGrouping.USER.getConfigValue()));

        auditor.addActivity(session, operation, resource, false);
        auditor.addActivity(session, operation, resource, true);
        auditor.addActivity(anotherSession, operation, resource, true);
        assertEquals(1, auditor.auditStorage.size());
        assertEquals(
                2,
                cast(auditor.auditStorage.get(
                        new Auditor.AuditKey(
                                session.getPrincipal(),
                                null)
                ), UserActivity.UserActivityOperationsGropedByIP.class).operations.size()
        );
        auditor.dump();
        assertEquals(0, auditor.auditStorage.size());
    }

    private <T extends UserActivity> T cast(final UserActivity userActivity, final Class<T> clazz) {
        return clazz.cast(userActivity);
    }

    @Test
    public void shouldBuildRightLogMessage() throws Exception {
        final UserOperationsActivityAuditor auditor = createAuditor();
        final AclOperation anotherOperation = AclOperation.ALTER;
        final ResourcePattern anotherResource = new ResourcePattern(
                ResourceType.DELEGATION_TOKEN,
                "ANOTHER_RESOURCE_NAME",
                PatternType.LITERAL
        );

        final ArgumentCaptor<String> logCaptor = ArgumentCaptor.forClass(String.class);
        auditor.addActivity(session, operation, resource, false);
        auditor.addActivity(session, anotherOperation, anotherResource, true);
        auditor.dump();

        verify(logger).info(logCaptor.capture());

        final String expectedPrefix = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME (%s) was active since ",
                InetAddress.getLocalHost()
        );

        assertTrue(logCaptor.getValue().startsWith(expectedPrefix));
        final String timestampStr =
                logCaptor.getValue()
                        .substring(
                                expectedPrefix.length(),
                                logCaptor.getValue().indexOf(": ")
                        );
        final Instant instant = Instant.parse(timestampStr);
        final long diffSeconds = Math.abs(ChronoUnit.SECONDS.between(instant, Instant.now()));
        assertTrue(diffSeconds < 3);

        final Set<String> loggedOperations = Arrays.stream(logCaptor.getValue()
                .substring(logCaptor.getValue().indexOf(": ") + 1)
                .split(",")).map(String::trim).collect(Collectors.toSet());


        assertThat(
                loggedOperations,
                containsInAnyOrder(
                        "Deny ALL on CLUSTER:RESOURCE_NAME",
                        "Allow ALTER on DELEGATION_TOKEN:ANOTHER_RESOURCE_NAME"
                )
        );
    }

    @Test
    public void shouldBuildRightLogMessageForPrincipalGrouping() throws Exception {
        final UserOperationsActivityAuditor auditor =
                createAuditor(Map.of(
                        AuditorConfig.AGGREGATION_PERIOD_CONF,
                        10L,
                        AuditorConfig.AGGREGATION_GROUPING_CONF,
                        AuditorConfig.AggregationGrouping.USER.getConfigValue()));
        final AclOperation anotherOperation = AclOperation.ALTER;
        final ResourcePattern anotherResource = new ResourcePattern(
                ResourceType.DELEGATION_TOKEN,
                "ANOTHER_RESOURCE_NAME",
                PatternType.LITERAL
        );

        final ArgumentCaptor<String> logCaptor = ArgumentCaptor.forClass(String.class);
        auditor.addActivity(session, operation, resource, false);
        auditor.addActivity(session, anotherOperation, anotherResource, true);
        auditor.dump();

        verify(logger).info(logCaptor.capture());

        final String expectedPrefix =
                "PRINCIPAL_TYPE:PRINCIPAL_NAME was active since ";

        assertTrue(logCaptor.getValue().startsWith(expectedPrefix));
        final String timestampStr =
                logCaptor.getValue()
                        .substring(
                                expectedPrefix.length(),
                                logCaptor.getValue().indexOf(". ")
                        );
        final Instant instant = Instant.parse(timestampStr);
        final long diffSeconds = Math.abs(ChronoUnit.SECONDS.between(instant, Instant.now()));
        assertTrue(diffSeconds < 3);

        final Set<String> loggedOperations = Arrays.stream(logCaptor.getValue()
                .substring(logCaptor.getValue().indexOf(": ") + 1)
                .split(",")).map(String::trim).collect(Collectors.toSet());

        assertThat(
                loggedOperations,
                containsInAnyOrder(
                        "Deny ALL on CLUSTER:RESOURCE_NAME",
                        "Allow ALTER on DELEGATION_TOKEN:ANOTHER_RESOURCE_NAME")
        );
    }

    private UserOperationsActivityAuditor createAuditor() {
        return createAuditor(Map.of(AuditorConfig.AGGREGATION_PERIOD_CONF, 10L));
    }

    private UserOperationsActivityAuditor createAuditor(final Map<String, ?> props) {
        final UserOperationsActivityAuditor auditor =
                new UserOperationsActivityAuditor(logger);
        auditor.configure(props);
        return auditor;
    }

}
