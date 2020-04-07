/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserActivityAuditorTest {

    @Mock
    private Logger logger;

    private Session session;
    private Operation operation;
    private Resource resource;

    @BeforeEach
    void setUp() throws Exception {
        final KafkaPrincipal principal = new KafkaPrincipal("PRINCIPAL_TYPE", "PRINCIPAL_NAME");
        session = new Session(principal, InetAddress.getLocalHost());
        resource =
            new Resource(
                ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.CLUSTER),
                "resource",
                PatternType.LITERAL
            );
        operation = Operation.fromJava(AclOperation.ALTER);
    }

    @Test
    public void shouldDumpMessagesWhenStop() {
        final Auditor auditor = spy(createAuditor());
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

    private UserActivityAuditor createAuditor() {
        final UserActivityAuditor auditor = new UserActivityAuditor(logger);
        auditor.configure(ImmutableMap.of(AuditorConfig.AGGREGATION_PERIOD_CONF, Long.MAX_VALUE));
        return auditor;
    }
}
