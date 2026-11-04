/*
 * Copyright 2026 Aiven Oy https://aiven.io
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
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.common.ClusterResource;
import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.network.ClientInformation;
import org.apache.kafka.common.network.ListenerName;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.requests.RequestContext;
import org.apache.kafka.common.requests.RequestHeader;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.network.KafkaAuthorizerServerInfo;

import io.aiven.kafka.auth.json.reader.AclJsonReader;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Measures how authorizer lookups scale with the number of ACLs.
 *
 * <p>Requests go through {@link AivenAclAuthorizerV2#authorize} with Kafka's {@link Action} flags, so metrics are
 * included; denial logging is off. The authorizer is started with Kafka's {@link KafkaAuthorizerServerInfo}, and
 * forks use the broker's JVM options from {@code kafka-run-class.sh} with its default 1 GB heap.
 *
 * <p>Cache-miss benchmarks use a new resource name on every call. Each iteration starts after an ACL file reload,
 * so with an empty verdict cache.
 *
 * <p>Run with, for example:
 * {@code java -jar build/libs/*-jmh.jar AclScaleBenchmark -p aclCount=1000,20000 -rf json -rff acl-scale.json}.
 * Override the heap with {@code -jvmArgsAppend "-Xms8g -Xmx8g"}.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.SampleTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(
    value = 1,
    jvmArgs = {
        "-server", "-XX:+UseG1GC", "-XX:MaxGCPauseMillis=20", "-XX:InitiatingHeapOccupancyPercent=35",
        "-XX:+ExplicitGCInvokesConcurrent", "-XX:MaxInlineLevel=15", "-Djava.awt.headless=true"
    },
    jvmArgsAppend = {"-Xms1G", "-Xmx1G"})
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
public class AclScaleBenchmark {

    /** ACL file check interval in milliseconds; the plugin default is 10000. */
    static final int REFRESH_INTERVAL_MS = 50;

    /** Input ACLs, see {@link AclFileGenerator}. */
    @Param({"1000", "6000", "20000"})
    int aclCount;

    @Param({"REGEX", "NATIVE"})
    AclFileGenerator.Profile profile;

    @Param({"10"})
    int aclsPerUser;

    /** Every N-th {@code NATIVE} ACL is a DENY rule; 0 disables them. */
    @Param({"20"})
    int denyEvery;

    Path tmpDir;
    Path aclFile;
    AivenAclAuthorizerConfig config;
    AivenAclAuthorizerV2 authorizer;
    int entryCount;
    long sequence;

    AuthorizableRequestContext firstUserProduce;
    AuthorizableRequestContext lastUserProduce;
    AuthorizableRequestContext lastUserJoinGroup;
    AuthorizableRequestContext unknownUserProduce;
    AuthorizableRequestContext firstUserInitProducerId;
    AuthorizableRequestContext unknownUserInitProducerId;

    String firstUserTopicPrefix;
    String lastUserTopicPrefix;
    String lastUserGroupPrefix;
    List<Action> firstUserTopic;

    @Setup(Level.Trial)
    public void setup() throws IOException {
        try {
            tmpDir = Files.createTempDirectory("acl-scale-benchmark");
            aclFile = tmpDir.resolve("acl.json");
            final AclFileGenerator generator = new AclFileGenerator(profile, aclCount, aclsPerUser, denyEvery);
            entryCount = generator.write(aclFile);

            final Map<String, String> configs = Map.of(
                "aiven.acl.authorizer.configuration", aclFile.toString(),
                "aiven.acl.authorizer.log.denials", "false",
                "aiven.acl.authorizer.config.refresh.interval", Integer.toString(REFRESH_INTERVAL_MS));
            config = new AivenAclAuthorizerConfig(configs);
            authorizer = new AivenAclAuthorizerV2();
            authorizer.configure(configs);
            final Endpoint endpoint = new Endpoint("SSL", SecurityProtocol.SSL, "localhost", 9093);
            authorizer.start(new KafkaAuthorizerServerInfo(
                new ClusterResource("benchmark-cluster"), 0, List.of(endpoint), endpoint, List.of()));

            final String first = generator.firstUser();
            final String last = generator.lastUser();
            final KafkaPrincipal unknown = user(AclFileGenerator.UNKNOWN_USER);
            firstUserProduce = requestContext(ApiKeys.PRODUCE, user(first));
            lastUserProduce = requestContext(ApiKeys.PRODUCE, user(last));
            lastUserJoinGroup = requestContext(ApiKeys.JOIN_GROUP, user(last));
            unknownUserProduce = requestContext(ApiKeys.PRODUCE, unknown);
            firstUserInitProducerId = requestContext(ApiKeys.INIT_PRODUCER_ID, user(first));
            unknownUserInitProducerId = requestContext(ApiKeys.INIT_PRODUCER_ID, unknown);

            firstUserTopicPrefix = generator.firstUserTopicPrefix();
            lastUserTopicPrefix = generator.lastUserTopicPrefix();
            lastUserGroupPrefix = generator.lastUserGroupPrefix();
            firstUserTopic = action(AclOperation.WRITE, ResourceType.TOPIC, firstUserTopicPrefix + "cached");

            verifySetup();
        } catch (final IOException | RuntimeException e) {
            tearDown();
            throw e;
        }
    }

    /**
     * Moves an identical copy over the ACL file and waits until the authorizer has reloaded it into an empty cache.
     * The atomic move ensures the authorizer never reads a partly written file.
     */
    @Setup(Level.Iteration)
    public void reloadAcls() throws IOException, InterruptedException {
        hitAllowed();
        final Path copy = Files.copy(aclFile, tmpDir.resolve("acl.json.tmp"), StandardCopyOption.REPLACE_EXISTING);
        Files.move(copy, aclFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (authorizer.getEstimatedCacheSizeEntries() != 0) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("The authorizer did not reload " + aclFile);
            }
            Thread.sleep(REFRESH_INTERVAL_MS);
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws IOException {
        if (authorizer != null) {
            authorizer.close();
        }
        if (aclFile != null) {
            Files.deleteIfExists(aclFile);
        }
        if (tmpDir != null) {
            Files.deleteIfExists(tmpDir);
        }
    }

    /** Cache miss allowed by the first user's first writable rule, after scanning every DENY rule. */
    @Benchmark
    public List<AuthorizationResult> missAllowedByFirstAcl() {
        return authorizer.authorize(firstUserProduce, action(AclOperation.WRITE, ResourceType.TOPIC,
            firstUserTopicPrefix + sequence++));
    }

    /** Cache miss allowed by the last user's last writable rule, near the end of the file. */
    @Benchmark
    public List<AuthorizationResult> missAllowedByLastAcl() {
        return authorizer.authorize(lastUserProduce, action(AclOperation.WRITE, ResourceType.TOPIC,
            lastUserTopicPrefix + sequence++));
    }

    /** Cache miss for a consumer joining a group; for {@code REGEX} only a catch-all rule at the end matches. */
    @Benchmark
    public List<AuthorizationResult> missGroupRead() {
        return authorizer.authorize(lastUserJoinGroup, action(AclOperation.READ, ResourceType.GROUP,
            lastUserGroupPrefix + sequence++));
    }

    /** Cache miss for a user without ACLs: every rule is scanned, then the request is denied. */
    @Benchmark
    public List<AuthorizationResult> missDenied() {
        return authorizer.authorize(unknownUserProduce, action(AclOperation.WRITE, ResourceType.TOPIC,
            firstUserTopicPrefix + sequence++));
    }

    /** Cache hit for an allowed request. */
    @Benchmark
    public List<AuthorizationResult> hitAllowed() {
        return authorizer.authorize(firstUserProduce, firstUserTopic);
    }

    /** Cache hit for a denied request. */
    @Benchmark
    public List<AuthorizationResult> hitDenied() {
        return authorizer.authorize(unknownUserProduce, firstUserTopic);
    }

    /** Uncached check behind InitProducerId when the producer lacks IdempotentWrite on the cluster. */
    @Benchmark
    public AuthorizationResult authorizeByResourceTypeAllowed() {
        return authorizer.authorizeByResourceType(firstUserInitProducerId, AclOperation.WRITE, ResourceType.TOPIC);
    }

    /** As above, for a user without ACLs, so every rule is checked. */
    @Benchmark
    public AuthorizationResult authorizeByResourceTypeDenied() {
        return authorizer.authorizeByResourceType(unknownUserInitProducerId, AclOperation.WRITE, ResourceType.TOPIC);
    }

    /** Parses the ACL file and builds a new verdict cache, as on every ACL file change. */
    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 3)
    @Measurement(iterations = 10)
    public VerdictCache loadAcls() {
        return VerdictCache.create(new AclJsonReader(aclFile).read(), config.getCacheMaxSizePercentage(),
            config.getCacheExpireAfterAccess());
    }

    private void verifySetup() {
        final int loaded = new AclJsonReader(aclFile).read().size();
        if (loaded != entryCount) {
            throw new IllegalStateException("Expected " + entryCount + " ACL entries but read " + loaded);
        }
        expect(missAllowedByFirstAcl(), AuthorizationResult.ALLOWED, "first user's topic");
        expect(missAllowedByLastAcl(), AuthorizationResult.ALLOWED, "last user's topic");
        expect(missGroupRead(), AuthorizationResult.ALLOWED, "last user's group");
        expect(missDenied(), AuthorizationResult.DENIED, "unknown user");
        expect(hitAllowed(), AuthorizationResult.ALLOWED, "first user's cached topic");
        expect(List.of(authorizeByResourceTypeAllowed()), AuthorizationResult.ALLOWED, "authorizeByResourceType");
        expect(List.of(authorizeByResourceTypeDenied()), AuthorizationResult.DENIED, "authorizeByResourceType");
    }

    private static void expect(final List<AuthorizationResult> actual, final AuthorizationResult expected,
                               final String what) {
        if (!actual.equals(List.of(expected))) {
            throw new IllegalStateException("Unexpected verdict for " + what + ": " + actual);
        }
    }

    private static KafkaPrincipal user(final String name) {
        return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, name);
    }

    /** One action with the flags Kafka's {@code AuthHelper} uses for produce and group requests. */
    private static List<Action> action(final AclOperation operation, final ResourceType type, final String name) {
        return List.of(new Action(operation, new ResourcePattern(type, name, PatternType.LITERAL), 1, true, true));
    }

    private static AuthorizableRequestContext requestContext(final ApiKeys apiKey, final KafkaPrincipal principal) {
        return new RequestContext(
            new RequestHeader(apiKey, apiKey.latestVersion(), "benchmark-client", 1),
            "connection-id",
            InetAddress.getLoopbackAddress(),
            principal,
            new ListenerName("SSL"),
            SecurityProtocol.SSL,
            ClientInformation.EMPTY,
            false);
    }
}
