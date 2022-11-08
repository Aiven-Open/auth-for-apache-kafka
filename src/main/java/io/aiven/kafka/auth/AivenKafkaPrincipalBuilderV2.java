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

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.authenticator.DefaultKafkaPrincipalBuilder;
import org.apache.kafka.common.utils.Time;

import io.aiven.kafka.auth.utils.TimeWithTimer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AivenKafkaPrincipalBuilderV2 implements KafkaPrincipalSerde, KafkaPrincipalBuilder, Configurable {
    private static final DefaultKafkaPrincipalBuilder DEFAULT_KAFKA_PRINCIPAL_BUILDER =
        new DefaultKafkaPrincipalBuilder(null, null);
    private static final Logger LOGGER = LoggerFactory.getLogger(AivenKafkaPrincipalBuilderV2.class);
    private final TimeWithTimer time;
    private volatile PrincipalMappers principalMappers;

    public AivenKafkaPrincipalBuilderV2() {
        this.time = new TimeWithTimer(Time.SYSTEM);
    }

    public AivenKafkaPrincipalBuilderV2(final TimeWithTimer time) {
        this.time = time;
    }

    @Override
    public byte[] serialize(final KafkaPrincipal principal) {
        return DEFAULT_KAFKA_PRINCIPAL_BUILDER.serialize(principal);
    }

    @Override
    public KafkaPrincipal deserialize(final byte[] bytes) {
        return DEFAULT_KAFKA_PRINCIPAL_BUILDER.deserialize(bytes);
    }

    @Override
    public void configure(final java.util.Map<String, ?> configs) {
        String configFileLocation = (String) configs.get("aiven.kafka.principal.builder.configuration");
        if (configFileLocation == null) {
            // Kafka didn't pass us custom configuration keys, revert to default
            configFileLocation = "/opt/aiven-kafka/aiven_kafka_principal_mappings.json";
        }

        String refreshTimeoutStr = (String) configs.get(
            "aiven.kafka.principal.builder.configuration.refresh.timeout");
        if (refreshTimeoutStr == null) {
            refreshTimeoutStr = "10000";
        }
        final long refreshTimeout = Long.parseLong(refreshTimeoutStr);

        String cacheCapacityStr = (String) configs.get(
            "aiven.kafka.principal.builder.configuration.cache.capacity");
        if (cacheCapacityStr == null) {
            cacheCapacityStr = "10000";
        }
        final long cacheCapacity = Long.parseLong(cacheCapacityStr);

        principalMappers = new PrincipalMappers(
            configFileLocation, refreshTimeout, time, cacheCapacity);
    }

    /* Map a ssl principal (subject) to a Kafka principal (type + name).*/
    public KafkaPrincipal mapSslPrincipal(final String sslPrincipal) {
        return principalMappers.match(sslPrincipal);
    }

    /** Entrypoint. */
    public KafkaPrincipal build(final AuthenticationContext context) {
        if (context instanceof PlaintextAuthenticationContext) {
            return KafkaPrincipal.ANONYMOUS;
        } else if (context instanceof SslAuthenticationContext) {
            final SSLSession sslSession = ((SslAuthenticationContext) context).session();
            try {
                return mapSslPrincipal(sslSession.getPeerPrincipal().getName());
            } catch (final SSLPeerUnverifiedException ex) {
                LOGGER.warn("Failed to verify client certificate, ({})", sslSession.getPeerHost(), ex);
                return new KafkaPrincipal("Invalid", "UNKNOWN");
            }
        } else if (context instanceof SaslAuthenticationContext) {
            final SaslServer saslServer = ((SaslAuthenticationContext) context).server();
            return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, saslServer.getAuthorizationID());
        } else {
            throw new IllegalArgumentException("Unhandled authentication context type: "
                + context.getClass().getName());
        }
    }
}
