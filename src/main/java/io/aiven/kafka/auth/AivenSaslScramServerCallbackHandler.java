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
        LOGGER.debug("Using configuration file {}", configFileLocation);
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
     * Supports two modes:
     * 1. Pre-computed SCRAM credentials (preferred) - directly uses stored salt, iterations, keys
     * 2. Plaintext passwords (legacy) - generates SCRAM credentials from plaintext
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
                    // Option 1: Check for pre-computed SCRAM credentials (preferred)
                    if (usernamePassword.scramCredentials() != null) {
                        final UsernamePassword.ScramCredentialEntry credEntry =
                            usernamePassword.scramCredentials().get(mechanismName);
                        if (credEntry != null) {
                            try {
                                final byte[] salt = java.util.Base64.getDecoder().decode(credEntry.salt());
                                final byte[] storedKey = java.util.Base64.getDecoder().decode(credEntry.storedKey());
                                final byte[] serverKey = java.util.Base64.getDecoder().decode(credEntry.serverKey());
                                LOGGER.debug("Using pre-computed SCRAM credentials for {}", username);
                                return new ScramCredential(salt, storedKey, serverKey, credEntry.iterations());
                            } catch (final IllegalArgumentException e) {
                                LOGGER.error("Failed to decode SCRAM credentials for {}", username, e);
                                return null;
                            }
                        }
                    }

                    // Option 2: Fall back to plaintext password (legacy)
                    final String storedPassword = usernamePassword.password();
                    if (storedPassword != null) {
                        LOGGER.debug("Generating SCRAM credentials from plaintext password for {}", username);
                        return formatter.generateCredential(storedPassword, mechanismIterations);
                    }

                    LOGGER.error("Authentication failed for {}, no password or scram_credentials set", username);
                    return null;
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
