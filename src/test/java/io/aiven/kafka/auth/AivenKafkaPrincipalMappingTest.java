package io.aiven.kafka.auth;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import io.aiven.kafka.auth.json.AivenKafkaPrincipalMapping;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AivenKafkaPrincipalMappingTest {

    @Test
    public void testAivenKafkaPrincipalMappingEntry() {
        AivenKafkaPrincipalMapping entry = new AivenKafkaPrincipalMapping(
            "^CN=p_(.*)_s$", // subject_matcher
            "pass", // principal_name
            "SpecialUser" // principal_type
        );

        assertTrue(entry.matches("CN=p_green_s"));
        KafkaPrincipal result = entry.buildKafkaPrincipal("CN=p_green_s");
        assertNotNull(result);
        assertEquals("SpecialUser", result.getPrincipalType());
        assertEquals("pass", result.getName());

        assertFalse(entry.matches("CN=fail"));

        // Omit principal_name and principal_type
        entry = new AivenKafkaPrincipalMapping(
            "^CN=p_(.*)_s$", // subject_matcher
            null, // principal_name
            null // principal_type
        );

        assertTrue(entry.matches("CN=p_green_s"));
        result = entry.buildKafkaPrincipal("CN=p_green_s");
        assertNotNull(result);
        assertEquals(KafkaPrincipal.USER_TYPE, result.getPrincipalType());
        assertEquals("CN=p_green_s", result.getName());
    }
}
