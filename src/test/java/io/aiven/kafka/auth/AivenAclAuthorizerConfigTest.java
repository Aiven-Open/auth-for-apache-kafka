/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;

import io.aiven.kafka.auth.audit.NoAuditor;
import io.aiven.kafka.auth.audit.UserActivityAuditor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AivenAclAuthorizerConfigTest {

    @Test
    void correctMinimalConfig() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.configuration", "/test");

        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(properties);
        assertEquals("/test", config.getConfigFile().getAbsolutePath());
        assertEquals(NoAuditor.class, config.getAuditor().getClass());
    }

    @Test
    void correctFullConfig() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.configuration", "/test");
        properties.put("aiven.acl.authorizer.auditor.class.name", UserActivityAuditor.class.getName());
        properties.put("aiven.acl.authorizer.auditor.aggregation.period", "123");

        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(properties);
        assertEquals("/test", config.getConfigFile().getAbsolutePath());
        assertEquals(UserActivityAuditor.class, config.getAuditor().getClass());
    }

    @Test
    void missingConfigPath() {
        final Map<String, String> properties = new HashMap<>();

        final Throwable t = assertThrows(
            ConfigException.class,
            () -> new AivenAclAuthorizerConfig(properties));
        assertEquals(
            "Missing required configuration \"aiven.acl.authorizer.configuration\" which has no default value.",
            t.getMessage()
        );
    }

    @Test
    void incorrectAuditorClass() {
        final Map<String, String> properties = new HashMap<>();
        properties.put("aiven.acl.authorizer.configuration", "/test");
        properties.put("aiven.acl.authorizer.auditor.class.name", ArrayList.class.getName());

        final AivenAclAuthorizerConfig config = new AivenAclAuthorizerConfig(properties);
        final Throwable t = assertThrows(
            KafkaException.class,
            config::getAuditor);
        assertEquals(
            "java.util.ArrayList is not an instance of io.aiven.kafka.auth.audit.Auditor",
            t.getMessage()
        );
    }
}
