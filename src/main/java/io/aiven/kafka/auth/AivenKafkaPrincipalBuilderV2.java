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

import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.security.authenticator.DefaultKafkaPrincipalBuilder;

import io.aiven.kafka.auth.utils.TimeWithTimer;

public class AivenKafkaPrincipalBuilderV2 extends AivenKafkaPrincipalBuilder implements KafkaPrincipalSerde {
    private static final DefaultKafkaPrincipalBuilder DEFAULT_KAFKA_PRINCIPAL_BUILDER =
        new DefaultKafkaPrincipalBuilder(null, null);

    public AivenKafkaPrincipalBuilderV2() {
        super();
    }

    public AivenKafkaPrincipalBuilderV2(final TimeWithTimer time) {
        super(time);
    }

    @Override
    public byte[] serialize(final KafkaPrincipal principal) {
        return DEFAULT_KAFKA_PRINCIPAL_BUILDER.serialize(principal);
    }

    @Override
    public KafkaPrincipal deserialize(final byte[] bytes) {
        return DEFAULT_KAFKA_PRINCIPAL_BUILDER.deserialize(bytes);
    }
}
