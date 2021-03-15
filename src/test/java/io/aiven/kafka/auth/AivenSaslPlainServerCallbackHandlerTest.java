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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.security.plain.PlainLoginModule;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenSaslPlainServerCallbackHandlerTest {
    static final String USERS_JSON = "[{\"username\":\"testuser\",\"password\":\"testpassword\"}]";

    @Test
    public void testAivenSaslPlainServerCallbackHandler() throws IOException {
        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-plain-handler");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd.json");

        final File passwdJson = new File(configFilePath.toString());

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
}
