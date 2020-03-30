import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import io.aiven.kafka.auth.AivenAclAuthorizer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenAclAuthorizerTest {
    static final String ACL_JSON =
        "[{\"principal_type\":\"User\",\"principal\":\"^pass$\","
            + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"}]";
    static final String ACL_JSON_NOTYPE =
        "[{\"principal\":\"^pass$\",\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"}]";
    static final String ACL_JSON_LONG = "["
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-0$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-1$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-2$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-3$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-4$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-5$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-6$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-7$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-8$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-9$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-10$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-11$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal_type\":\"User\",\"principal\":\"^pass-12$\","
        + "\"operation\":\"^Read$\",\"resource\":\"^Topic:(.*)$\"},"
        + "{\"principal\":\"^pass-notype$\",\"operation\":\"^Read$\","
        + "\"resource\":\"^Topic:(.*)$\"}"
        + "]";

    @TempDir
    Path tmpDir;

    @Test
    public void testAivenAclAuthorizer() throws IOException {
        final Path configFilePath = tmpDir.resolve("acl.json");

        Files.write(configFilePath, ACL_JSON.getBytes());

        final AivenAclAuthorizer auth = new AivenAclAuthorizer();
        final Map<String, String> configs = new HashMap();
        configs.put("aiven.acl.authorizer.configuration", configFilePath.toString());
        auth.configure(configs);

        // basic ACL checks
        assertTrue(auth.checkAcl("User", "pass", "Read", "Topic:Target"));
        assertFalse(auth.checkAcl("User", "fail", "Read", "Topic:Target"));
        assertFalse(auth.checkAcl("User", "pass", "Read", "Fail:Target"));
        assertFalse(auth.checkAcl("User", "pass", "FailRead", "Topic:Target"));
        assertFalse(auth.checkAcl("NonUser", "pass", "Read", "Topic:Target"));

        // reload logic
        assertFalse(auth.reloadAcls());
        final File aclJson = new File(configFilePath.toString());
        aclJson.setLastModified(aclJson.lastModified() + 10000);
        assertTrue(auth.reloadAcls());

        // Check support for undefined principal type
        Files.write(configFilePath, ACL_JSON_NOTYPE.getBytes());
        aclJson.setLastModified(aclJson.lastModified() + 20000);
        assertTrue(auth.reloadAcls());

        assertTrue(auth.checkAcl("User", "pass", "Read", "Topic:Target"));
        assertTrue(auth.checkAcl("NonUser", "pass", "Read", "Topic:Target"));

        // Longer configs trigger caching of results
        Files.write(configFilePath, ACL_JSON_LONG.getBytes());
        aclJson.setLastModified(aclJson.lastModified() + 30000);
        assertTrue(auth.reloadAcls());

        // first iteration without cache
        assertTrue(auth.checkAcl("User", "pass-1", "Read", "Topic:Target"));
        assertFalse(auth.checkAcl("User", "fail-1", "Read", "Topic:Target"));

        // second iteration from cache
        assertTrue(auth.checkAcl("User", "pass-1", "Read", "Topic:Target"));
        assertFalse(auth.checkAcl("User", "fail-1", "Read", "Topic:Target"));
    }
}
