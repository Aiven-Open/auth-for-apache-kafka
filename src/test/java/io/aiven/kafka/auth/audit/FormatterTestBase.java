/*
 * Copyright 2021 Aiven Oy https://aiven.io
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
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import kafka.network.RequestChannel;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FormatterTestBase {

    protected RequestChannel.Session session;

    protected Operation operation;

    protected Resource resource;

    protected AuditorDumpFormatter formatter;

    protected Operation anotherOperation;

    protected Resource anotherResource;

    protected RequestChannel.Session anotherSession;

    protected InetAddress anotherInetAddress;

    private final AuditorConfig.AggregationGrouping aggregationGrouping;

    protected FormatterTestBase(final AuditorConfig.AggregationGrouping aggregationGrouping) {
        this.aggregationGrouping = aggregationGrouping;
    }

    void setUp() throws Exception {
        final KafkaPrincipal principal = new KafkaPrincipal("PRINCIPAL_TYPE", "PRINCIPAL_NAME");
        session = new RequestChannel.Session(principal, InetAddress.getLocalHost());
        anotherInetAddress = InetAddress.getByName("192.168.0.1");
        anotherSession = new RequestChannel.Session(principal, anotherInetAddress);
        resource =
                new Resource(
                        ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.CLUSTER),
                        "resource",
                        PatternType.LITERAL
                );
        operation = Operation.fromJava(AclOperation.ALTER);

        anotherOperation = Operation.fromJava(AclOperation.ALTER);
        anotherResource = new Resource(
                ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.DELEGATION_TOKEN),
                "ANOTHER_RESOURCE_NAME",
                PatternType.LITERAL
        );
    }

    protected void zeroOperations(final ZonedDateTime now, final String expected) {
        final Map<Auditor.AuditKey, UserActivity> dump = new HashMap<>();
        dump.put(createAuditKey(session), createUserActivity(now));
        formatAndAssert(dump, expected);
    }

    protected void twoOperations(final ZonedDateTime now, final String expected) {
        final Map<Auditor.AuditKey, UserActivity> dump = new HashMap<>();
        final UserActivity userActivity = createUserActivity(now);
        userActivity.addOperation(new UserOperation(session.clientAddress(), operation, resource, false));
        userActivity.addOperation(
                new UserOperation(session.clientAddress(), anotherOperation, anotherResource, true));
        dump.put(createAuditKey(session), userActivity);

        formatAndAssert(dump, expected);
    }

    protected Auditor.AuditKey createAuditKey(final RequestChannel.Session session) {
        switch (aggregationGrouping) {
            case USER:
                return new Auditor.AuditKey(session.principal(), null);
            case USER_AND_IP:
                return new Auditor.AuditKey(session.principal(), session.clientAddress());
            default:
                throw new IllegalArgumentException("Unknown aggregation grouping: " + aggregationGrouping);
        }
    }

    protected UserActivity createUserActivity(final ZonedDateTime time) {
        switch (aggregationGrouping) {
            case USER:
                return new UserActivity.UserActivityOperationsGropedByIP(time);
            case USER_AND_IP:
                return new UserActivity.UserActivityOperations(time);
            default:
                throw new IllegalArgumentException("Unknown aggregation grouping: " + aggregationGrouping);
        }
    }

    protected void formatAndAssert(final Map<Auditor.AuditKey, UserActivity> dump, final String... expected) {
        final List<String> entries = formatter.format(dump);

        assertEquals(expected.length, entries.size());
        assertEquals(Arrays.asList(expected), entries);
    }
}
