/*
 * Copyright 2025 Aiven Oy https://aiven.io
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
import java.net.Inet4Address;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.network.ClientInformation;
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.requests.RequestContext;
import org.apache.kafka.common.requests.RequestHeader;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthByResouceTypeTest {
    @TempDir
    Path tmpDir;
    Path configFilePath;
    final AivenAclAuthorizerV2 auth = new AivenAclAuthorizerV2();
    Map<String, String> configs;

    @BeforeEach
    void setUp() throws IOException {
        configFilePath = tmpDir.resolve("acl.json");
        configs = Map.of("aiven.acl.authorizer.configuration", configFilePath.toString(),
                         "aiven.acl.authorizer.config.refresh.interval", "10");
        auth.configure(configs);

        Files.copy(this.getClass().getResourceAsStream("/test_acls_for_authorize_by_resource_type.json"),
                   configFilePath);
        startAuthorizer();
    }

    @AfterEach
    void tearDown() {
        auth.close();
    }

    private void startAuthorizer() {
        final AuthorizerServerInfo serverInfo = mock(AuthorizerServerInfo.class);
        when(serverInfo.endpoints()).thenReturn(List.of());
        auth.start(serverInfo);
    }

    private AuthorizableRequestContext requestCtx(
            final String principalType,
            final String name) throws IOException {
        return new RequestContext(
                new RequestHeader(ApiKeys.METADATA, (short) 0, "some-client-id", 123),
                "connection-id",
                Inet4Address.getByName("127.0.0.1"),
                new KafkaPrincipal(principalType, name),
                new ListenerName("SSL"),
                SecurityProtocol.SSL,
                ClientInformation.EMPTY,
                false);
    }

    static final class AuthByResourceTypeTestcase {
        final String name;
        final AclOperation operation;
        final ResourceType resourceType;
        final AuthorizationResult expectedResult;

        public AuthByResourceTypeTestcase(final String name, final AclOperation operation,
                                          final ResourceType resourceType, final AuthorizationResult expectedResult) {
            this.name = name;
            this.operation = operation;
            this.resourceType = resourceType;
            this.expectedResult = expectedResult;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<AuthByResourceTypeTestcase> authByResouceTypeTestcaseProvider() {
        return Stream.of(
                new AuthByResourceTypeTestcase("test_user_no_acls", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_allow_some", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.ALLOWED),
                new AuthByResourceTypeTestcase("test_user_deny_all", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_deny_prefix", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_allow_read", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_allow_all", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.ALLOWED),
                new AuthByResourceTypeTestcase("test_user_allow_wildcard_host", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.ALLOWED),
                new AuthByResourceTypeTestcase("test_user_allow_localhost", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.ALLOWED),
                new AuthByResourceTypeTestcase("test_user_deny_host", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_deny_write", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_deny_write", AclOperation.READ, ResourceType.TOPIC,
                        AuthorizationResult.ALLOWED),
                new AuthByResourceTypeTestcase("test_user_deny_prefix_write", AclOperation.WRITE, ResourceType.TOPIC,
                        AuthorizationResult.DENIED),
                new AuthByResourceTypeTestcase("test_user_deny_prefix_write", AclOperation.READ, ResourceType.TOPIC,
                        AuthorizationResult.ALLOWED)
        );
    }

    @ParameterizedTest
    @MethodSource("authByResouceTypeTestcaseProvider")
    void authByResouceType(final AuthByResourceTypeTestcase testcase) throws IOException {
        final AuthorizableRequestContext requestCtx = requestCtx("User", testcase.name);
        assertThat(auth.authorizeByResourceType(requestCtx, testcase.operation, testcase.resourceType))
            .isEqualTo(testcase.expectedResult);
        assertThat(auth.default_authorizeByResourceType(requestCtx, testcase.operation, testcase.resourceType))
            .isEqualTo(testcase.expectedResult);
    }
}
