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

public class PrincipalFormatterTest extends FormatterTestBase {

    public PrincipalFormatterTest() {
        super(AuditorConfig.AggregationGrouping.USER);
    }

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        formatter = new PrincipalFormatter();
    }

    @Test
    public void shouldBuildRightLogMessageZeroOperations() throws Exception {
        final ZonedDateTime now = ZonedDateTime.now();
        final String expected = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME was active since %s.",
                now.format(AuditorDumpFormatter.dateFormatter()));
        zeroOperations(now, expected);
    }

    @Test
    public void shouldBuildRightLogMessageTwoOperations() throws Exception {
        final ZonedDateTime now = ZonedDateTime.now();
        final String expected = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME was active since %s. %s: "
                        + "Deny Alter on Cluster:resource, Allow Alter on DelegationToken:ANOTHER_RESOURCE_NAME",
                now.format(AuditorDumpFormatter.dateFormatter()),
                InetAddress.getLocalHost()
        );

        twoOperations(now, expected);
    }

    @Test
    public void shouldBuildRightLogMessageTwoOperationsTwoIps() throws Exception {
        final ZonedDateTime now = ZonedDateTime.now();
        final String expected = String.format(
                "PRINCIPAL_TYPE:PRINCIPAL_NAME was active since %s. "
                        + "%s: Deny Alter on Cluster:resource, "
                        + "%s: Allow Alter on DelegationToken:ANOTHER_RESOURCE_NAME",
                now.format(AuditorDumpFormatter.dateFormatter()),
                InetAddress.getLocalHost(),
                anotherInetAddress
        );

        twoOperationsTwoIpAddresses(now, expected);
    }

    protected void twoOperationsTwoIpAddresses(final ZonedDateTime now, final String... expected) {
        final Map<Auditor.AuditKey, UserActivity> dump = new HashMap<>();

        final UserActivity userActivity = createUserActivity(now);
        userActivity.addOperation(
                new UserOperation(session.clientAddress(), operation, resource, false));
        userActivity.addOperation(
                new UserOperation(anotherSession.clientAddress(), anotherOperation, anotherResource, true));
        dump.put(createAuditKey(session), userActivity);

        formatAndAssert(dump, expected);
    }

}
