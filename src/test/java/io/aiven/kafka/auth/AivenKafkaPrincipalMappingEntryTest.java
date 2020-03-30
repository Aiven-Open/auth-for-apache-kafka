package io.aiven.kafka.auth;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AivenKafkaPrincipalMappingEntryTest {

    @Test
    public void testAivenKafkaPrincipalMappingEntry() {
        AivenKafkaPrincipalMappingEntry entry = new AivenKafkaPrincipalMappingEntry(
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
        entry = new AivenKafkaPrincipalMappingEntry(
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
