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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

import kafka.network.RequestChannel.Session;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import kafka.security.auth.ResourceType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

public class AivenAclAuthorizerV2Test {
    static final Resource TOPIC_RESOURCE = new Resource(
            ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.TOPIC),
            "Target",
            PatternType.LITERAL
    );
    static final Resource GROUP_RESOURCE = new Resource(
            ResourceType.fromJava(org.apache.kafka.common.resource.ResourceType.GROUP),
            "Target",
            PatternType.LITERAL
    );
    static final Operation READ_OPERATION = Operation.fromJava(AclOperation.READ);
    static final Operation CREATE_OPERATION = Operation.fromJava(AclOperation.CREATE);
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
    Path configFilePath;
    final AivenAclAuthorizerV2 auth = new AivenAclAuthorizerV2();
    Map<String, String> configs;

    @BeforeEach
    void setUp() {
        configFilePath = tmpDir.resolve("acl.json");
        configs = Map.of(
                "aiven.acl.authorizer.configuration", configFilePath.toString(),
                "aiven.acl.authorizer.config.refresh.interval", "10");
        auth.configure(configs);
    }

    @AfterEach
    void tearDown() {
        auth.close();
    }

    @Test
    public void testAivenAclAuthorizer() throws IOException, InterruptedException {
        Files.write(configFilePath, ACL_JSON.getBytes());
        Thread.sleep(100);

        // basic ACL checks
        assertThat(auth.authorize(startSessionFor("User", "pass"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();
        assertThat(auth.authorize(startSessionFor("User", "fail"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();
        assertThat(auth.authorize(startSessionFor("User", "pass"), READ_OPERATION, GROUP_RESOURCE)).isFalse();
        assertThat(auth.authorize(startSessionFor("User", "pass"), CREATE_OPERATION, TOPIC_RESOURCE)).isFalse();
        assertThat(auth.authorize(startSessionFor("NonUser", "pass"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // Check support for undefined principal type
        Files.write(configFilePath, ACL_JSON_NOTYPE.getBytes());
        Thread.sleep(100);

        assertThat(auth.authorize(startSessionFor("User", "pass"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();
        assertThat(auth.authorize(startSessionFor("NonUser", "pass"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();

        Files.write(configFilePath, ACL_JSON_LONG.getBytes());
        Thread.sleep(100);

        // first iteration without cache
        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();
        assertThat(auth.authorize(startSessionFor("User", "fail-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // second iteration from cache
        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();
        assertThat(auth.authorize(startSessionFor("User", "fail-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // Checking that wrong configuration leads to failed auth
        Files.write(configFilePath, "]".getBytes());
        Thread.sleep(100);
        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();
        assertThat(auth.authorize(startSessionFor("User", "fail-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // Checking that empty configuration leads to failed auth
        Files.write(configFilePath, "".getBytes());
        Thread.sleep(100);
        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();
        assertThat(auth.authorize(startSessionFor("User", "fail-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();
    }

    @Test
    public void testConfigReloading() throws IOException, InterruptedException {
        auth.configure(configs);
        assertThat(auth.authorize(startSessionFor("User", "pass"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // check that config is reloaded after file modification
        Files.write(configFilePath, ACL_JSON_LONG.getBytes());
        Thread.sleep(100);

        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();

        // check that config is reloaded after file deletion
        assertThat(configFilePath.toFile().delete()).isTrue();
        Thread.sleep(100);

        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // check that config is reloaded after directory deletion
        assertThat(Files.deleteIfExists(configFilePath.getParent().toAbsolutePath())).isTrue();
        Thread.sleep(100);

        assertThat(auth.authorize(startSessionFor("User", "pass-1"), READ_OPERATION, TOPIC_RESOURCE)).isFalse();

        // check that config reloaded after file and directory re-creation
        assertThat(tmpDir.toFile().mkdir()).isTrue();
        Thread.sleep(100);
        Files.write(configFilePath, ACL_JSON.getBytes());
        Thread.sleep(100);
        assertThat(auth.authorize(startSessionFor("User", "pass"), READ_OPERATION, TOPIC_RESOURCE)).isTrue();
    }

    private Session startSessionFor(final String principalType, final String name) throws UnknownHostException {
        return new Session(new KafkaPrincipal(principalType, name), InetAddress.getLocalHost());
    }
}
