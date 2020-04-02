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

import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.ScramLoginModule;

import io.aiven.kafka.auth.AivenSaslScramServerCallbackHandler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenSaslScramServerCallbackHandlerTest {
    static final String USERS_JSON = "[{\"username\":\"testuser\",\"password\":\"testpassword\"}]";

    @Test
    public void testAivenSaslPlainServerCallbackHandler() throws IOException {
        final Path tempPath = Files.createTempDirectory("test-aiven-kafka-sasl-scram-handler");
        final Path configFilePath = Paths.get(tempPath.toString(), "sasl_passwd.json");

        final File passwdJson = new File(configFilePath.toString());

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
}
