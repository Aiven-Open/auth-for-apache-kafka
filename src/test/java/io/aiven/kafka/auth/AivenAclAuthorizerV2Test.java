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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AccessControlEntryFilter;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.network.ClientInformation;
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.requests.RequestContext;
import org.apache.kafka.common.requests.RequestHeader;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourcePatternFilter;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AivenAclAuthorizerV2Test {
    static final ResourcePattern TOPIC_RESOURCE = new ResourcePattern(
        org.apache.kafka.common.resource.ResourceType.TOPIC,
        "Target",
        PatternType.LITERAL
    );
    static final ResourcePattern GROUP_RESOURCE = new ResourcePattern(
        org.apache.kafka.common.resource.ResourceType.GROUP,
        "Target",
        PatternType.LITERAL
    );
    static final AclOperation READ_OPERATION = AclOperation.READ;
    static final AclOperation CREATE_OPERATION = AclOperation.CREATE;

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
    public void testAclsMethodWhenListingEnabled() throws IOException {
        Files.copy(this.getClass().getResourceAsStream("/test_acls_for_acls_method.json"), configFilePath);
        startAuthorizer();

        assertThat(auth.acls(AclBindingFilter.ANY))
            .containsExactly(
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER_CONFIGS, AclPermissionType.ALLOW)
                ),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.DELETE, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.WRITE, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.DESCRIBE, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                    new AccessControlEntry(
                        "User:test\\-user", "*", AclOperation.DESCRIBE_CONFIGS, AclPermissionType.ALLOW
                    )),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "prefix\\.", PatternType.PREFIXED),
                    new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-admin", "*", AclOperation.CREATE, AclPermissionType.ALLOW)),
                new AclBinding(
                    new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                    new AccessControlEntry("User:test\\-admin", "*", AclOperation.DELETE, AclPermissionType.ALLOW))
            );


        assertThat(auth.acls(new AclBindingFilter(
            new ResourcePatternFilter(ResourceType.TOPIC, "xxx", PatternType.MATCH),
            new AccessControlEntryFilter("User:test\\-user", "*", AclOperation.ALTER_CONFIGS, AclPermissionType.ALLOW)
        ))).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER_CONFIGS, AclPermissionType.ALLOW))
        );

        assertThat(auth.acls(new AclBindingFilter(
            new ResourcePatternFilter(ResourceType.TOPIC, "prefix\\.example", PatternType.MATCH),
            AccessControlEntryFilter.ANY
        ))).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DESCRIBE, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new AccessControlEntry(
                    "User:test\\-user", "*", AclOperation.DESCRIBE_CONFIGS, AclPermissionType.ALLOW
                )),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "prefix\\.", PatternType.PREFIXED),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-admin", "*", AclOperation.CREATE, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-admin", "*", AclOperation.DELETE, AclPermissionType.ALLOW))
        );

        assertThat(auth.acls(new AclBindingFilter(
            new ResourcePatternFilter(ResourceType.TOPIC, "xxx", PatternType.MATCH),
            new AccessControlEntryFilter("User:test\\-user", "*", AclOperation.ANY, AclPermissionType.ALLOW)
        ))).containsExactly(
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.ALTER_CONFIGS, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DELETE, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.READ, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "xxx", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.WRITE, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DESCRIBE, AclPermissionType.ALLOW)),
            new AclBinding(
                new ResourcePattern(ResourceType.TOPIC, "*", PatternType.LITERAL),
                new AccessControlEntry("User:test\\-user", "*", AclOperation.DESCRIBE_CONFIGS, AclPermissionType.ALLOW))
        );
    }

    @Test
    public void testAclsMethodWhenListingDisabled() throws IOException {
        final var configsUpdated = new HashMap<>(configs);
        configsUpdated.put("aiven.acl.authorizer.list.acls.enabled", "false");
        auth.configure(configsUpdated);

        Files.copy(this.getClass().getResourceAsStream("/test_acls_for_acls_method.json"), configFilePath);
        startAuthorizer();

        assertThat(auth.acls(null))
            .isEmpty();
    }

    @Test
    public void testAivenAclAuthorizer() throws IOException, InterruptedException {
        Files.copy(this.getClass().getResourceAsStream("/acls_plain.json"), configFilePath);
        startAuthorizer();

        // basic ACL checks
        checkSingleAction(requestCtx("User", "pass"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("User", "fail"), action(READ_OPERATION, TOPIC_RESOURCE), false);
        checkSingleAction(requestCtx("User", "pass"), action(READ_OPERATION, GROUP_RESOURCE), false);
        checkSingleAction(requestCtx("User", "pass"), action(CREATE_OPERATION, TOPIC_RESOURCE), false);
        checkSingleAction(requestCtx("NonUser", "pass"), action(READ_OPERATION, TOPIC_RESOURCE), false);
        // Some checks in list
        final var listAuthorizeResult = auth.authorize(
            requestCtx("User", "pass"),
            List.of(
                action(READ_OPERATION, TOPIC_RESOURCE),
                action(READ_OPERATION, GROUP_RESOURCE),
                action(CREATE_OPERATION, TOPIC_RESOURCE)
            ));
        assertThat(listAuthorizeResult).isEqualTo(List.of(
            AuthorizationResult.ALLOWED,
            AuthorizationResult.DENIED,
            AuthorizationResult.DENIED
        ));
    }

    @Test
    public void testUndefinedPrincipalType() throws IOException, InterruptedException {
        Files.copy(this.getClass().getResourceAsStream("/acls_no_type.json"), configFilePath);
        startAuthorizer();

        checkSingleAction(requestCtx("User", "pass"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("NonUser", "pass"), action(READ_OPERATION, TOPIC_RESOURCE), true);
    }

    @Test
    public void testTopicPrefix() throws IOException, InterruptedException {
        Files.copy(this.getClass().getResourceAsStream("/acls_topic_prefix.json"), configFilePath);
        startAuthorizer();

        checkSingleAction(requestCtx("User", "pass"), action(READ_OPERATION, new ResourcePattern(
            org.apache.kafka.common.resource.ResourceType.TOPIC,
            "prefix-topic",
            PatternType.LITERAL
        )), true);
    }

    @Test
    public void testDeny() throws IOException, InterruptedException {
        Files.copy(this.getClass().getResourceAsStream("/acls_deny.json"), configFilePath);
        startAuthorizer();

        checkSingleAction(requestCtx("User", "whatever"), action(READ_OPERATION, new ResourcePattern(
            org.apache.kafka.common.resource.ResourceType.TOPIC,
            "test-topic",
            PatternType.LITERAL
        )), true);

        checkSingleAction(requestCtx("User", "whatever"), action(READ_OPERATION, new ResourcePattern(
            org.apache.kafka.common.resource.ResourceType.TOPIC,
            "topic-denied",
            PatternType.LITERAL
        )), false);
    }

    @Test
    public void testDenyPrefix() throws IOException, InterruptedException {
        Files.copy(this.getClass().getResourceAsStream("/acls_deny_prefix.json"), configFilePath);
        startAuthorizer();

        checkSingleAction(requestCtx("User", "user"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("User", "user"), action(CREATE_OPERATION, TOPIC_RESOURCE), true);

        final ResourcePattern deniedTopicResource = new ResourcePattern(
            org.apache.kafka.common.resource.ResourceType.TOPIC,
            "denied-topic",
            PatternType.LITERAL
        );

        checkSingleAction(requestCtx("User", "user"), action(READ_OPERATION, deniedTopicResource), true);
        checkSingleAction(requestCtx("User", "user"), action(CREATE_OPERATION, deniedTopicResource), false);
    }

    @Test
    public void testAuthorizerCache() throws IOException, InterruptedException {
        Files.copy(this.getClass().getResourceAsStream("/acls_full.json"), configFilePath);
        startAuthorizer();
        final var deniedResource = new ResourcePattern(
            org.apache.kafka.common.resource.ResourceType.TOPIC,
            "denied",
            PatternType.LITERAL
        );

        // first iteration without cache
        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("User", "pass-3"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("User", "pass-3"), action(READ_OPERATION, deniedResource), false);
        checkSingleAction(requestCtx("User", "fail-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);

        // second iteration from cache
        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("User", "pass-3"), action(READ_OPERATION, TOPIC_RESOURCE), true);
        checkSingleAction(requestCtx("User", "pass-3"), action(READ_OPERATION, deniedResource), false);
        checkSingleAction(requestCtx("User", "fail-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);
    }

    @Test
    public void testWrongConfiguration() throws IOException, InterruptedException {
        Files.write(configFilePath, "]".getBytes());
        startAuthorizer();

        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);
        checkSingleAction(requestCtx("User", "fail-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);
    }

    @Test
    public void testEmptyConfiguration() throws IOException, InterruptedException {
        Files.write(configFilePath, "".getBytes());
        startAuthorizer();

        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);
        checkSingleAction(requestCtx("User", "fail-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);
    }

    @Test
    public void testConfigReloading() throws IOException, InterruptedException {
        startAuthorizer();

        checkSingleAction(requestCtx("User", "pass"), action(READ_OPERATION, TOPIC_RESOURCE), false);

        // check that config is reloaded after file modification
        Files.copy(this.getClass().getResourceAsStream("/acls_full.json"), configFilePath);
        Thread.sleep(100);

        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), true);

        // check that config is reloaded after file deletion
        assertThat(configFilePath.toFile().delete()).isTrue();
        Thread.sleep(100);

        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);

        // check that config is reloaded after directory deletion
        assertThat(Files.deleteIfExists(configFilePath.getParent().toAbsolutePath())).isTrue();
        Thread.sleep(100);

        checkSingleAction(requestCtx("User", "pass-1"), action(READ_OPERATION, TOPIC_RESOURCE), false);

        // check that config reloaded after file and directory re-creation
        assertThat(tmpDir.toFile().mkdir()).isTrue();
        Thread.sleep(100);
        Files.copy(this.getClass().getResourceAsStream("/acls_plain.json"), configFilePath);
        Thread.sleep(100);
        checkSingleAction(requestCtx("User", "pass"), action(READ_OPERATION, TOPIC_RESOURCE), true);
    }

    @Test
    public void testStart() {
        final AuthorizerServerInfo serverInfo = mock(AuthorizerServerInfo.class);
        when(serverInfo.endpoints()).thenReturn(
            List.of(
                new Endpoint("PLAINTEXT", SecurityProtocol.PLAINTEXT, "localhost", 9092),
                new Endpoint("SSL", SecurityProtocol.SSL, "localhost", 9093)
            )
        );
        assertThat(auth.start(serverInfo)).allSatisfy(
            (endpoint, completionStage) ->
                assertThatNoException().isThrownBy(
                    () -> completionStage.toCompletableFuture().get(0, TimeUnit.MICROSECONDS))
        );
    }

    private void startAuthorizer() {
        final AuthorizerServerInfo serverInfo = mock(AuthorizerServerInfo.class);
        when(serverInfo.endpoints()).thenReturn(List.of());
        auth.start(serverInfo);
    }

    private AuthorizableRequestContext requestCtx(final String principalType, final String name) {
        return new RequestContext(
            new RequestHeader(ApiKeys.METADATA, (short) 0, "some-client-id", 123),
            "connection-id",
            InetAddress.getLoopbackAddress(),
            new KafkaPrincipal(principalType, name),
            new ListenerName("SSL"),
            SecurityProtocol.SSL,
            ClientInformation.EMPTY,
            false
        );
    }

    private Action action(final AclOperation operation, final ResourcePattern resource) {
        return new Action(operation, resource, 0, true, true);
    }

    private void checkSingleAction(final AuthorizableRequestContext requestCtx,
                                   final Action action,
                                   final boolean allowed) {
        final List<AuthorizationResult> result = auth.authorize(requestCtx, List.of(action));
        assertThat(result).isEqualTo(List.of(allowed ? AuthorizationResult.ALLOWED : AuthorizationResult.DENIED));
    }
}
