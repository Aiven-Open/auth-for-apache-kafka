import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.AivenAclAuthorizer;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType;
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
        assertTrue(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "pass"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
        assertFalse(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "fail"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
        assertFalse(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "pass"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.GROUP),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
        assertFalse(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "pass"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.CREATE),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
        assertFalse(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("NonUser", "pass"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );

        // reload logic
        assertFalse(auth.reloadAcls());
        final File aclJson = new File(configFilePath.toString());
        aclJson.setLastModified(aclJson.lastModified() + 10000);
        assertTrue(auth.reloadAcls());

        // Check support for undefined principal type
        Files.write(configFilePath, ACL_JSON_NOTYPE.getBytes());
        aclJson.setLastModified(aclJson.lastModified() + 20000);
        assertTrue(auth.reloadAcls());

        assertTrue(auth.authorize(
            new Session(
                new KafkaPrincipal("User", "pass"),
                InetAddress.getLocalHost()
            ),
            Operation.fromJava(AclOperation.READ),
            new Resource(
                ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                "Target",
                PatternType.LITERAL
            )
        ));
        assertTrue(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("NonUser", "pass"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );

        // Longer configs trigger caching of results
        Files.write(configFilePath, ACL_JSON_LONG.getBytes());
        aclJson.setLastModified(aclJson.lastModified() + 30000);
        assertTrue(auth.reloadAcls());

        // first iteration without cache
        assertTrue(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "pass-1"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
        assertFalse(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "fail-1"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );

        // second iteration from cache
        assertTrue(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "pass-1"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
        assertFalse(
            auth.authorize(
                new Session(
                    new KafkaPrincipal("User", "fail-1"),
                    InetAddress.getLocalHost()
                ),
                Operation.fromJava(AclOperation.READ),
                new Resource(
                    ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
                    "Target",
                    PatternType.LITERAL
                )
            )
        );
    }
}
