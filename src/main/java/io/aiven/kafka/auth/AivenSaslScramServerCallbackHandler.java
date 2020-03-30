/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.scram.ScramCredential;
import org.apache.kafka.common.security.scram.ScramCredentialCallback;
import org.apache.kafka.common.security.scram.ScramLoginModule;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

import io.aiven.kafka.auth.json.UsernamePassword;
import io.aiven.kafka.auth.json.reader.JsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;
import io.aiven.kafka.auth.json.reader.UsernamePasswordJsonReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AivenSaslScramServerCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AivenSaslScramServerCallbackHandler.class);

    private String configFileLocation;
    private String mechanismName;
    private int mechanismIterations;
    private ScramFormatter formatter;
    private JsonReader<UsernamePassword> jsonReader;

    @Override
    public void configure(final Map<String, ?> configs,
                          final String mechanism,
                          final List<AppConfigurationEntry> jaasConfigEntries) {
        configFileLocation = JaasContext.configEntryOption(
            jaasConfigEntries, "users.config", ScramLoginModule.class.getName());
        LOGGER.info("Using configuration file {}", configFileLocation);
        mechanismName = mechanism;
        final ScramMechanism scramMechanism = ScramMechanism.forMechanismName(mechanismName);
        if (scramMechanism != null) {
            mechanismIterations = scramMechanism.minIterations();
            try {
                formatter = new ScramFormatter(scramMechanism);
            } catch (final NoSuchAlgorithmException e) {
                LOGGER.error(
                    "Error configuring SASL/SCRAM callback, unsupported mechanism {}",
                    mechanismName
                );
            }
        } else {
            LOGGER.error(
                "Error configuring SASL/SCRAM callback, unrecognized mechanism {}",
                mechanismName
            );
        }
        jsonReader = new UsernamePasswordJsonReader(Paths.get(configFileLocation));
    }

    @Override
    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        String username = null;
        for (final Callback callback : callbacks) {
            // The order of these callbacks is fixed
            if (callback instanceof NameCallback) {
                final NameCallback nameCallback = (NameCallback) callback;
                username = nameCallback.getDefaultName();
            } else if (callback instanceof ScramCredentialCallback) {
                final ScramCredentialCallback credCallback = (ScramCredentialCallback) callback;
                final ScramCredential creds = getScramCreds(username);
                credCallback.scramCredential(creds);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    /**
     * Generate SCRAM creds for given username.
     */
    public ScramCredential getScramCreds(final String username) {
        if (formatter == null) {
            LOGGER.error(
                "Authentication failed for {}, no credential formatter set for mechanism {}",
                username, mechanismName
            );
            return null;
        }

        try {
            final List<UsernamePassword> usernamePasswords = jsonReader.read();
            for (final UsernamePassword usernamePassword : usernamePasswords) {
                if (username.equals(usernamePassword.name())) {
                    final String storedPassword = usernamePassword.password();
                    if (storedPassword == null) {
                        LOGGER.error("Authentication failed for {}, no password set", username);
                        return null;
                    }
                    return formatter.generateCredential(storedPassword, mechanismIterations);
                }
            }
        } catch (final JsonReaderException ex) {
            LOGGER.error("Failed to read configuration file", ex);
            return null;
        }

        LOGGER.error("Authentication failed for {}, unknown user", username);
        return null;
    }

    @Override
    public void close() throws KafkaException {
    }
}
