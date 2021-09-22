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
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link PrincipalAndIpFormatter}.
 */
public class PrincipalAndIpFormatterTest extends FormatterTestBase {

    public PrincipalAndIpFormatterTest() {
        super(AuditorConfig.AggregationGrouping.USER_AND_IP);
    }

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        formatter = new PrincipalAndIpFormatter();
    }

    @Test
    public void shouldBuildRightLogMessageZeroOperations() throws Exception {
        final ZonedDateTime now = ZonedDateTime.now();
        final String expected = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME (%s) was active since %s",
                InetAddress.getLocalHost(),
                now.format(AuditorDumpFormatter.dateFormatter())
        );
        zeroOperations(now, expected);
    }

    @Test
    public void shouldBuildRightLogMessageTwoOperations() throws Exception {
        final ZonedDateTime now = ZonedDateTime.now();
        final String expected = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME (%s) was active since %s: "
                        + "Deny ALTER on CLUSTER:resource, "
                        + "Allow ALTER on DELEGATION_TOKEN:ANOTHER_RESOURCE_NAME",
                InetAddress.getLocalHost(),
                now.format(AuditorDumpFormatter.dateFormatter())
        );

        twoOperations(now, expected);
    }

    @Test
    public void shouldBuildRightLogMessageTwoOperationsTwoIps() throws Exception {
        final ZonedDateTime now = ZonedDateTime.now();
        final String expected1 = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME (%s) was active since %s: Deny ALTER on CLUSTER:resource",
                InetAddress.getLocalHost(),
                now.format(AuditorDumpFormatter.dateFormatter())
        );
        final String expected2 = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME (%s) was active since %s: "
                        + "Allow ALTER on DELEGATION_TOKEN:ANOTHER_RESOURCE_NAME",
                anotherInetAddress,
                now.format(AuditorDumpFormatter.dateFormatter())
        );

        twoOperationsTwoIpAddresses(now, expected1, expected2);
    }

    protected void twoOperationsTwoIpAddresses(final ZonedDateTime now, final String... expected) {
        final Map<Auditor.AuditKey, UserActivity> dump = new HashMap<>();

        final UserActivity userActivity = createUserActivity(now);
        userActivity.addOperation(new UserOperation(session.clientAddress(), operation, resource, false));
        dump.put(createAuditKey(session), userActivity);

        final UserActivity anotherUserActivity = createUserActivity(now);
        anotherUserActivity.addOperation(
                new UserOperation(anotherSession.clientAddress(), anotherOperation, anotherResource, true));
        dump.put(createAuditKey(anotherSession), anotherUserActivity);

        formatAndAssert(dump, expected);
    }

}
