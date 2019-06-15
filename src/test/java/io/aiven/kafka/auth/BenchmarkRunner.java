package io.aiven.kafka.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

/**
 * SSL principal mapping benchmark.
 *
 * <p>Run with {@code mvn integration-test}.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
public class BenchmarkRunner {
  AivenKafkaPrincipalBuilder builder;
  Path configFilePath;

  @Setup
  public void setup() throws IOException {
    configFilePath = Files.createTempDirectory("test-aiven-kafka-principal-builder")
            .resolve("benchmark_config.json");
    Files.copy(this.getClass().getResourceAsStream("/benchmark_config.json"), configFilePath);

    builder = new AivenKafkaPrincipalBuilder();
    Map<String, String> config = new HashMap<>();
    config.put("aiven.kafka.principal.builder.configuration", configFilePath.toString());
    builder.configure(config);
  }

  @Benchmark
  public void benchmarkLastEntry(Blackhole bh) {
    bh.consume(builder.mapSslPrincipal("bbb"));
  }

  @Benchmark
  public void benchmarkNonExistent(Blackhole bh) {
    bh.consume(builder.mapSslPrincipal("non-existent"));
  }
}
