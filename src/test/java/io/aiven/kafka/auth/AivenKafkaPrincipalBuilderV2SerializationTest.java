/*
 * Copyright 2021 Aiven Oy https://aiven.io
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

import java.util.stream.Stream;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

public class AivenKafkaPrincipalBuilderV2SerializationTest {
    private AivenKafkaPrincipalBuilderV2 builder;

    @BeforeEach
    public void initTests() {
        builder = new AivenKafkaPrincipalBuilderV2(null);
    }

    @ParameterizedTest
    @MethodSource("principalProvider")
    public void testSerialization(final KafkaPrincipal principal) {
        final byte[] serializedPrincipal = builder.serialize(principal);
        final KafkaPrincipal deserializedPrincipal = builder.deserialize(serializedPrincipal);
        assertThat(deserializedPrincipal).isEqualTo(principal);
    }

    private static Stream<KafkaPrincipal> principalProvider() {
        return Stream.of(
            new KafkaPrincipal("some type", "some name", true),
            KafkaPrincipal.ANONYMOUS
        );
    }
}
