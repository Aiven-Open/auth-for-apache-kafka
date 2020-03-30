import io.aiven.kafka.auth.AivenAclEntry;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AivenAclEntryTest {

    @Test
    public void testAivenAclEntry() {
        // Basic test: defined principal type plus principal, operation and resource regex
        AivenAclEntry entry = new AivenAclEntry(
            "User", // principal type
            "^CN=p_(.*)_s$", // principal
            "^(Describe|Read)$", // operation
            "^Topic:p_(.*)_s", // resource,
            null // resource pattern
        );

        assertTrue(entry.check("User", "CN=p_pass_s", "Read", "Topic:p_pass_s"));
        assertFalse(entry.check("User", "CN=fail", "Read", "Topic:p_pass_s"));
        assertFalse(entry.check("User", "CN=p_pass_s", "Write", "Topic:p_pass_s"));
        assertFalse(entry.check("User", "CN=p_pass_s", "Read", "Topic:fail"));
        assertFalse(entry.check("NonUser", "CN=p_pass_s", "Read", "Topic:p_pass_s"));

        // Test with principal undefined
        entry = new AivenAclEntry(
            null, // principal type
            "^CN=p_(.*)_s$", // principal
            "^(Describe|Read)$", // operation
            "^Topic:p_(.*)_s", // resource
            null // resource pattern
        );

        assertTrue(entry.check("User", "CN=p_pass_s", "Read", "Topic:p_pass_s"));
        assertTrue(entry.check("NonUser", "CN=p_pass_s", "Read", "Topic:p_pass_s"));
        assertFalse(entry.check("User", "CN=fail", "Read", "Topic:p_pass_s"));
        assertFalse(entry.check("User", "CN=p_pass_s", "Read", "Topic:fail"));

        // Test resources defined by pattern
        entry = new AivenAclEntry(
            "User", // principal type
            "^CN=p_(?<username>[a-z0-9]+)_s$", // principal
            "^(Describe|Read)$", // operation
            null, // resource
            "^Topic:p_${username}_s\\$" // resource pattern
        );

        assertTrue(entry.check("User", "CN=p_user1_s", "Read", "Topic:p_user1_s"));
        assertTrue(entry.check("User", "CN=p_user2_s", "Read", "Topic:p_user2_s"));
        assertFalse(entry.check("User", "CN=p_user1_s", "Read", "Topic:p_user2_s"));
        assertFalse(entry.check("User", "CN=p_user2_s", "Read", "Topic:p_user1_s"));
    }
}
