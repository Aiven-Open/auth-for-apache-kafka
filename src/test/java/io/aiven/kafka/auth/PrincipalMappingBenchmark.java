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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

/**
 * SSL principal mapping benchmark.
 *
 * <p>Run with {@code gradlew jmh}
 * or if you want to run faster, use
 * {@code gradlew jmhJar && java -jar ./build/libs/auth-for-apache-kafka-*-jmh.jar -to 30 -w 1 -wi 0 -i 1}
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class PrincipalMappingBenchmark {
    AivenKafkaPrincipalBuilderV2 builder;
    Path configFilePath;

    @Setup
    public void setup() throws IOException {
        configFilePath = Files.createTempDirectory("test-aiven-kafka-principal-builder")
            .resolve("benchmark_config.json");
        Files.copy(this.getClass().getResourceAsStream("/benchmark_config.json"), configFilePath);

        builder = new AivenKafkaPrincipalBuilderV2();
        final Map<String, String> config = new HashMap<>();
        config.put("aiven.kafka.principal.builder.configuration", configFilePath.toString());
        builder.configure(config);
    }

    @Benchmark
    public void benchmarkLastEntry(final Blackhole bh) throws InterruptedException {
        bh.consume(builder.mapSslPrincipal("bbb"));
    }

    @Benchmark
    public void benchmarkNonExistent(final Blackhole bh) throws InterruptedException {
        bh.consume(builder.mapSslPrincipal("non-existent"));
    }
}
