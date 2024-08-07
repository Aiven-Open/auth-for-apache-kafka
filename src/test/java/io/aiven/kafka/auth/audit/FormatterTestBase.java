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
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FormatterTestBase {

    protected Session session;

    protected AclOperation operation;

    protected ResourcePattern resource;

    protected AuditorDumpFormatter formatter;

    protected AclOperation anotherOperation;

    protected ResourcePattern anotherResource;

    protected Session anotherSession;

    protected InetAddress anotherInetAddress;

    private final AuditorConfig.AggregationGrouping aggregationGrouping;

    protected FormatterTestBase(final AuditorConfig.AggregationGrouping aggregationGrouping) {
        this.aggregationGrouping = aggregationGrouping;
    }

    void setUp() throws Exception {
        final KafkaPrincipal principal = new KafkaPrincipal("PRINCIPAL_TYPE", "PRINCIPAL_NAME");
        session = new Session(principal, InetAddress.getLocalHost());
        anotherInetAddress = InetAddress.getByName("192.168.0.1");
        anotherSession = new Session(principal, anotherInetAddress);
        resource =
                new ResourcePattern(
                        ResourceType.CLUSTER,
                        "resource",
                        PatternType.LITERAL
                );
        operation = AclOperation.ALTER;

        anotherOperation = AclOperation.ALTER;
        anotherResource = new ResourcePattern(
                ResourceType.DELEGATION_TOKEN,
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
        userActivity.addOperation(new UserOperation(session.getClientAddress(), operation, resource, false));
        userActivity.addOperation(
                new UserOperation(session.getClientAddress(), anotherOperation, anotherResource, true));
        dump.put(createAuditKey(session), userActivity);

        formatAndAssert(dump, expected);
    }

    protected Auditor.AuditKey createAuditKey(final Session session) {
        switch (aggregationGrouping) {
            case USER:
                return new Auditor.AuditKey(session.getPrincipal(), null);
            case USER_AND_IP:
                return new Auditor.AuditKey(session.getPrincipal(), session.getClientAddress());
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
        assertEquals(new HashSet<>(Arrays.asList(expected)), new HashSet<>(entries));
    }
}
