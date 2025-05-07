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
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Authorizer::authorizeByResourceType benchmark compares AivenAclAuthorizerV2's
 * implementation against Kafka's Authorizer default implementation.
 *
 * <p>Run with {@code gradlew jmh}
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class AuthByResourceTypeBenchmark {
    Path tmpDir;
    Path configFilePath;
    final AivenAclAuthorizerV2 auth = new AivenAclAuthorizerV2();
    Map<String, String> configs;

    AuthorizableRequestContext testUserNoAcls;
    AuthorizableRequestContext testUserAllowSome;
    AuthorizableRequestContext testUserDenyAll;
    AuthorizableRequestContext testUserDenyPrefix;
    AuthorizableRequestContext testUserAllowRead;
    AuthorizableRequestContext testUserAllowAll;
    AuthorizableRequestContext testUserDenyWrite;
    AuthorizableRequestContext testUserDenyPrefixWrite;

    @Setup
    public void setup() throws IOException {
        tmpDir = Files.createTempDirectory("test-aiven-kafka-authorizer");
        configFilePath = tmpDir.resolve("acl.json");
        configs = Map.of(
                "aiven.acl.authorizer.configuration", configFilePath.toString(),
                "aiven.acl.authorizer.config.refresh.interval", "10");
        auth.configure(configs);

        Files.copy(this.getClass().getResourceAsStream("/benchmark_acls_for_authorize_by_resource_type.json"),
                   configFilePath);
        final AuthorizerServerInfo serverInfo = mock(AuthorizerServerInfo.class);
        when(serverInfo.endpoints()).thenReturn(List.of());
        auth.start(serverInfo);

        configFilePath = Files.createTempDirectory("test-aiven-kafka-principal-builder")
            .resolve("benchmark_config.json");
        Files.copy(this.getClass().getResourceAsStream("/benchmark_config.json"), configFilePath);

        testUserNoAcls = requestCtx("User", "test_user_no_acls");
        testUserAllowSome = requestCtx("User", "test_user_allow_some");
        testUserDenyAll = requestCtx("User", "test_user_deny_all");
        testUserDenyPrefix = requestCtx("User", "test_user_deny_prefix");
        testUserAllowRead = requestCtx("User", "test_user_allow_read");
        testUserAllowAll = requestCtx("User", "test_user_allow_all");
        testUserDenyWrite = requestCtx("User", "test_user_deny_write");
        testUserDenyPrefixWrite = requestCtx("User", "test_user_deny_prefix_write");
    }

    @TearDown
    public void tearDown() {
        auth.close();
    }

    private AuthorizableRequestContext requestCtx(
            final String principalType,
            final String name) {
        return new RequestContext(
                new RequestHeader(ApiKeys.METADATA, (short) 0, "some-client-id", 123),
                "connection-id",
                InetAddress.getLoopbackAddress(),
                new KafkaPrincipal(principalType, name),
                new ListenerName("SSL"),
                SecurityProtocol.SSL,
                ClientInformation.EMPTY,
                false);
    }

    @Benchmark
    public void benchmarkAivenAclAuthorizerV2(final Blackhole bh) throws InterruptedException {
        bh.consume(auth.authorizeByResourceType(testUserNoAcls, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserAllowSome, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserDenyAll, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserDenyPrefix, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserAllowRead, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserAllowAll, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserDenyWrite, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserDenyWrite, AclOperation.READ,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserDenyPrefixWrite, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.authorizeByResourceType(testUserDenyPrefixWrite, AclOperation.READ,
                ResourceType.TOPIC));
    }

    @Benchmark
    public void benchmarkKafkaDefaultImpl(final Blackhole bh) throws InterruptedException {
        bh.consume(auth.default_authorizeByResourceType(testUserNoAcls, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserAllowSome, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserDenyAll, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserDenyPrefix, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserAllowRead, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserAllowAll, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserDenyWrite, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserDenyWrite, AclOperation.READ,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserDenyPrefixWrite, AclOperation.WRITE,
                ResourceType.TOPIC));
        bh.consume(auth.default_authorizeByResourceType(testUserDenyPrefixWrite, AclOperation.READ,
                ResourceType.TOPIC));
    }
}
