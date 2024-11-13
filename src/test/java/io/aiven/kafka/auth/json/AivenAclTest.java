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

package io.aiven.kafka.auth.json;

import org.apache.kafka.common.acl.AclOperation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenAclTest {
    @Test
    public void testAivenAclEntry() {
        // Basic test: defined principal type plus principal, operation and resource regex
        AivenAcl entry = new AivenAcl(
            "User", // principal type
            "^CN=p_(.*)_s$", // principal
            "*", // host
            "^(Describe|Read)$", // operation
            "^Topic:p_(.*)_s", // resource,
            null, // resource pattern
            null, // resource literal
            null, // resource prefix
            null, // permission type
            false // hidden
        );

        assertTrue(entry.match("User",  "CN=p_pass_s", "*", AclOperation.READ, "Topic:p_pass_s"));
        assertFalse(entry.match("User", "CN=fail", "*", AclOperation.READ, "Topic:p_pass_s"));
        assertFalse(entry.match("User", "CN=p_pass_s", "*", AclOperation.WRITE, "Topic:p_pass_s"));
        assertFalse(entry.match("User", "CN=p_pass_s", "*", AclOperation.READ, "Topic:fail"));
        assertFalse(entry.match("NonUser", "CN=p_pass_s", "*", AclOperation.READ, "Topic:p_pass_s"));

        // Test with principal undefined
        entry = new AivenAcl(
            null, // principal type
            "^CN=p_(.*)_s$", // principal
            "*", // host
            "^(Describe|Read)$", // operation
            "^Topic:p_(.*)_s", // resource
            null, // resource pattern
            null, // resource literal
            null, // resource prefix
            null, // permission type
            false // hidden
        );

        assertTrue(entry.match("User", "CN=p_pass_s", "*", AclOperation.READ, "Topic:p_pass_s"));
        assertTrue(entry.match("NonUser", "CN=p_pass_s", "*", AclOperation.READ, "Topic:p_pass_s"));
        assertFalse(entry.match("User", "CN=fail", "*", AclOperation.READ, "Topic:p_pass_s"));
        assertFalse(entry.match("User", "CN=p_pass_s", "*", AclOperation.READ, "Topic:fail"));

        // Test resources defined by pattern
        entry = new AivenAcl(
            "User", // principal type
            "^CN=p_(?<username>[a-z0-9]+)_s$", // principal
            "*", // host
            "^(Describe|Read)$", // operation
            null, // resource
            "^Topic:p_${username}_s\\$", // resource pattern
            null, // resource literal
            null, // resource prefix
            null, // permission type
            false // hidden
        );

        assertTrue(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:p_user1_s"));
        assertTrue(entry.match("User", "CN=p_user2_s", "*", AclOperation.READ, "Topic:p_user2_s"));
        assertFalse(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:p_user2_s"));
        assertFalse(entry.match("User", "CN=p_user2_s", "*", AclOperation.READ, "Topic:p_user1_s"));

        // Test resources defined by literal match
        entry = new AivenAcl(
                "User", // principal type
                "^CN=p_(?<username>[a-z0-9]+)_s$", // principal
                "*", // host
                "^(Describe|Read)$", // operation
                null, // resource
                null, // resource pattern
                "Topic:^(][", // invalid regex just to show that the match is a literal string
                null, // resource prefix
                null, // permission type
                false // hidden
        );

        assertTrue(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:^(]["));
        assertFalse(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:wrong_topic"));


        // Test resources defined by prefix match
        entry = new AivenAcl(
                "User", // principal type
                "^CN=p_(?<username>[a-z0-9]+)_s$", // principal
                "*", // host
                "^(Describe|Read)$", // operation
                null, // resource
                null, // resource pattern
                null, // resource literal
                "Topic:organizationA.", // invalid regex just to show that the match is a literal string
                null, // permission type
                false // hidden
        );
        assertTrue(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:organizationA.topic1"));
        assertTrue(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:organizationA.topic2"));
        assertTrue(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:organizationA."));
        assertFalse(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:organizationB.topic1"));
        assertFalse(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:organizationA"));
        assertFalse(entry.match("User", "CN=p_user1_s", "*", AclOperation.READ, "Topic:AAAorganizationA."));
    }
}
