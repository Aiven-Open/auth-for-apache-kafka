/**
 * Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;

import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.utils.Time;

import io.aiven.kafka.auth.utils.TimeWithTimer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AivenKafkaPrincipalBuilder implements KafkaPrincipalBuilder, Configurable {
    private static final Logger LOGGER = LoggerFactory.getLogger(AivenKafkaPrincipalBuilder.class);
    private final TimeWithTimer time;
    private volatile PrincipalMappers principalMappers;

    public AivenKafkaPrincipalBuilder() {
        this.time = new TimeWithTimer(Time.SYSTEM);
    }

    /** Visible for testing. */
    public AivenKafkaPrincipalBuilder(final TimeWithTimer time) {
        this.time = time;
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

    /** Map a ssl principal (subject) to a Kafka principal (type + name). */
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
