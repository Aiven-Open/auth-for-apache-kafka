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

package io.aiven.kafka.auth;

import javax.security.auth.login.AppConfigurationEntry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.security.plain.PlainLoginModule;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenSaslPlainServerCallbackHandlerTest {
    static final String USERS_JSON = "[{\"username\":\"testuser\",\"password\":\"testpassword\"}]";

    @Test
    public void testAivenSaslPlainServerCallbackHandlerWithPlaintextPassword() throws IOException {
        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-plain-handler");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd.json");

        Files.write(configFilePath, USERS_JSON.getBytes());

        final Map<String, String> entryConfigs = new HashMap<String, String>();
        entryConfigs.put("users.config", configFilePath.toString());
        final AppConfigurationEntry entry = new AppConfigurationEntry(PlainLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryConfigs);
        final List<AppConfigurationEntry> jaasConfigs = new ArrayList<AppConfigurationEntry>();
        jaasConfigs.add(entry);

        final AivenSaslPlainServerCallbackHandler handler = new AivenSaslPlainServerCallbackHandler();
        handler.configure(null, "PLAIN", jaasConfigs);

        assertTrue(handler.authenticate("testuser", "testpassword".toCharArray()));
        assertFalse(handler.authenticate("testuser", "invalidpassword".toCharArray()));
        assertFalse(handler.authenticate("invaliduser", "testpassword".toCharArray()));
    }

    @Test
    public void testAivenSaslPlainServerCallbackHandlerWithScramCredentials() throws Exception {
        // Generate pre-computed SCRAM credentials for "testpassword"
        final ScramMechanism mechanism = ScramMechanism.SCRAM_SHA_256;
        final ScramFormatter formatter = new ScramFormatter(mechanism);
        final ScramCredential credential = formatter.generateCredential("testpassword", mechanism.minIterations());

        final java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
        final String salt = encoder.encodeToString(credential.salt());
        final String storedKey = encoder.encodeToString(credential.storedKey());
        final String serverKey = encoder.encodeToString(credential.serverKey());
        final int iterations = credential.iterations();

        final String usersJsonWithScram = "[{\"username\":\"testuser\",\"scram_credentials\":{"
            + "\"SCRAM-SHA-256\":{\"salt\":\"" + salt + "\","
            + "\"stored_key\":\"" + storedKey + "\","
            + "\"server_key\":\"" + serverKey + "\","
            + "\"iterations\":" + iterations + "}}}]";

        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-plain-handler-scram");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd_scram.json");

        Files.write(configFilePath, usersJsonWithScram.getBytes());

        final Map<String, String> entryConfigs = new HashMap<String, String>();
        entryConfigs.put("users.config", configFilePath.toString());
        final AppConfigurationEntry entry = new AppConfigurationEntry(PlainLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryConfigs);
        final List<AppConfigurationEntry> jaasConfigs = new ArrayList<AppConfigurationEntry>();
        jaasConfigs.add(entry);

        final AivenSaslPlainServerCallbackHandler handler = new AivenSaslPlainServerCallbackHandler();
        handler.configure(null, "PLAIN", jaasConfigs);

        // Should authenticate with correct password
        assertTrue(handler.authenticate("testuser", "testpassword".toCharArray()));
        // Should reject invalid password
        assertFalse(handler.authenticate("testuser", "invalidpassword".toCharArray()));
        // Should reject invalid user
        assertFalse(handler.authenticate("invaliduser", "testpassword".toCharArray()));
    }

    @Test
    public void testAivenSaslPlainServerCallbackHandlerWithScramSha512Credentials() throws Exception {
        // Test with SCRAM-SHA-512 credentials
        final ScramMechanism mechanism = ScramMechanism.SCRAM_SHA_512;
        final ScramFormatter formatter = new ScramFormatter(mechanism);
        final ScramCredential credential = formatter.generateCredential("mypassword", mechanism.minIterations());

        final java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
        final String salt = encoder.encodeToString(credential.salt());
        final String storedKey = encoder.encodeToString(credential.storedKey());
        final String serverKey = encoder.encodeToString(credential.serverKey());
        final int iterations = credential.iterations();

        final String usersJsonWithScram = "[{\"username\":\"alice\",\"scram_credentials\":{"
            + "\"SCRAM-SHA-512\":{\"salt\":\"" + salt + "\","
            + "\"stored_key\":\"" + storedKey + "\","
            + "\"server_key\":\"" + serverKey + "\","
            + "\"iterations\":" + iterations + "}}}]";

        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-plain-handler-scram512");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd_scram512.json");

        Files.write(configFilePath, usersJsonWithScram.getBytes());

        final Map<String, String> entryConfigs = new HashMap<String, String>();
        entryConfigs.put("users.config", configFilePath.toString());
        final AppConfigurationEntry entry = new AppConfigurationEntry(PlainLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryConfigs);
        final List<AppConfigurationEntry> jaasConfigs = new ArrayList<AppConfigurationEntry>();
        jaasConfigs.add(entry);

        final AivenSaslPlainServerCallbackHandler handler = new AivenSaslPlainServerCallbackHandler();
        handler.configure(null, "PLAIN", jaasConfigs);

        assertTrue(handler.authenticate("alice", "mypassword".toCharArray()));
        assertFalse(handler.authenticate("alice", "wrongpassword".toCharArray()));
    }
}
