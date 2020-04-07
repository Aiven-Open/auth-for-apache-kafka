/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import com.google.common.collect.ImmutableMap;
import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType;
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

    private Operation operation;

    private Resource resource;

    @BeforeEach
    void setUp() throws Exception {
        principal = new KafkaPrincipal("PRINCIPAL_TYPE", "PRINCIPAL_NAME");
        session = new Session(principal, InetAddress.getLocalHost());

        operation = Operation.fromJava(AclOperation.ALL);
        resource =
            new Resource(
                ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.CLUSTER),
                "RESOURCE_NAME",
                PatternType.LITERAL
            );
    }

    @Test
    public void shouldDumpMessagesWhenStop() {
        final Auditor auditor = spy(createAuditor());
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
            auditor.auditStorage.get(
                new Auditor.AuditKey(principal, InetAddress.getLocalHost())
            ).operations.size()
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
            auditor.auditStorage.get(
                new Auditor.AuditKey(
                    session.principal(),
                    session.clientAddress())
            ).operations.size()
        );
        assertEquals(
            1,
            auditor.auditStorage.get(
                new Auditor.AuditKey(
                    anotherSession.principal(),
                    anotherSession.clientAddress())
            ).operations.size()
        );
        auditor.dump();
        assertEquals(0, auditor.auditStorage.size());
    }

    @Test
    public void shouldBuildRightLogMessage() throws Exception {
        final UserOperationsActivityAuditor auditor = createAuditor();
        final Operation anotherOperation = Operation.fromJava(AclOperation.ALTER);
        final Resource anotherResource = new Resource(
            ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.DELEGATION_TOKEN),
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


        final String[] expectedOperations = new String[]{
            "Deny All on Cluster:RESOURCE_NAME",
            "Allow Alter on DelegationToken:ANOTHER_RESOURCE_NAME"
        };

        assertThat(loggedOperations, containsInAnyOrder(expectedOperations));
    }

    private UserOperationsActivityAuditor createAuditor() {
        final UserOperationsActivityAuditor auditor =
            new UserOperationsActivityAuditor(logger);
        auditor.configure(ImmutableMap.of(AuditorConfig.AGGREGATION_PERIOD_CONF, 10L));
        return auditor;
    }

}
