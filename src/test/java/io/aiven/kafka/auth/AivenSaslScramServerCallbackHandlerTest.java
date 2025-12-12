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

import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.ScramLoginModule;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenSaslScramServerCallbackHandlerTest {
    static final String USERS_JSON = "[{\"username\":\"testuser\",\"password\":\"testpassword\"}]";

    @Test
    public void testAivenSaslScramServerCallbackHandlerWithPlaintextPassword() throws IOException {
        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-scram-handler");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd.json");

        Files.write(configFilePath, USERS_JSON.getBytes());

        final Map<String, String> entryConfigs = new HashMap<String, String>();
        entryConfigs.put("users.config", configFilePath.toString());
        final AppConfigurationEntry entry = new AppConfigurationEntry(ScramLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryConfigs);
        final List<AppConfigurationEntry> jaasConfigs = new ArrayList<AppConfigurationEntry>();
        jaasConfigs.add(entry);

        // scram-sha-256
        AivenSaslScramServerCallbackHandler handler = new AivenSaslScramServerCallbackHandler();
        handler.configure(null, "SCRAM-SHA-256", jaasConfigs);

        ScramCredential creds = handler.getScramCreds("testuser");
        assertNotNull(creds);
        assertTrue(creds.iterations() == 4096);  // 4096 is the defined minIterations for SCRAM-SHA-256

        creds = handler.getScramCreds("invaliduser");
        assertNull(creds);

        // scram-sha-512
        handler = new AivenSaslScramServerCallbackHandler();
        handler.configure(null, "SCRAM-SHA-512", jaasConfigs);

        creds = handler.getScramCreds("testuser");
        assertNotNull(creds);
        assertTrue(creds.iterations() == 4096);  // 4096 is the defined minIterations for SCRAM-SHA-512

        creds = handler.getScramCreds("invaliduser");
        assertNull(creds);

        // invalid mechanism
        handler = new AivenSaslScramServerCallbackHandler();
        handler.configure(null, "SCRAM-SHA-768-invalid", jaasConfigs);

        creds = handler.getScramCreds("testuser");
        assertNull(creds);
    }

    @Test
    public void testAivenSaslScramServerCallbackHandlerWithPrecomputedCredentials() throws Exception {
        // Generate pre-computed SCRAM credentials for "testpassword"
        final ScramMechanism mechanism = ScramMechanism.forMechanismName("SCRAM-SHA-256");
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

        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-scram-handler-precomp");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd_precomp.json");

        Files.write(configFilePath, usersJsonWithScram.getBytes());

        final Map<String, String> entryConfigs = new HashMap<String, String>();
        entryConfigs.put("users.config", configFilePath.toString());
        final AppConfigurationEntry entry = new AppConfigurationEntry(ScramLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entryConfigs);
        final List<AppConfigurationEntry> jaasConfigs = new ArrayList<AppConfigurationEntry>();
        jaasConfigs.add(entry);

        final AivenSaslScramServerCallbackHandler handler = new AivenSaslScramServerCallbackHandler();
        handler.configure(null, "SCRAM-SHA-256", jaasConfigs);

        final ScramCredential creds = handler.getScramCreds("testuser");
        assertNotNull(creds);
        assertTrue(creds.iterations() == iterations);
        assertTrue(java.util.Arrays.equals(creds.salt(), credential.salt()));
        assertTrue(java.util.Arrays.equals(creds.storedKey(), credential.storedKey()));
        assertTrue(java.util.Arrays.equals(creds.serverKey(), credential.serverKey()));
    }
}
