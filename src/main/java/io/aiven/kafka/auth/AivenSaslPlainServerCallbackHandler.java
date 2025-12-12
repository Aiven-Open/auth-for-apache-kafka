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

import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.plain.PlainLoginModule;
import org.apache.kafka.common.security.scram.internals.ScramFormatter;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;

import io.aiven.kafka.auth.json.UsernamePassword;
import io.aiven.kafka.auth.json.reader.JsonReader;
import io.aiven.kafka.auth.json.reader.JsonReaderException;
import io.aiven.kafka.auth.json.reader.UsernamePasswordJsonReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AivenSaslPlainServerCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger LOGGER =
        LoggerFactory.getLogger(AivenSaslPlainServerCallbackHandler.class);

    private String configFileLocation;

    private JsonReader<UsernamePassword> jsonReader;

    @Override
    public void configure(final Map<String, ?> configs,
                          final String mechanism,
                          final List<AppConfigurationEntry> jaasConfigEntries) {
        configFileLocation = JaasContext.configEntryOption(
            jaasConfigEntries, "users.config", PlainLoginModule.class.getName());
        LOGGER.debug("Using configuration file {}", configFileLocation);
        jsonReader = new UsernamePasswordJsonReader(Paths.get(configFileLocation));
    }

    @Override
    public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
        String username = null;
        for (final Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                final NameCallback nameCallback = (NameCallback) callback;
                username = nameCallback.getDefaultName();
            } else if (callback instanceof PlainAuthenticateCallback) {
                final PlainAuthenticateCallback plainCallback = (PlainAuthenticateCallback) callback;
                final boolean authenticated = authenticate(username, plainCallback.password());
                plainCallback.authenticated(authenticated);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    /**
     * Check whether the given username is found and whether password is valid.
     * Supports both plaintext passwords and verification against pre-computed SCRAM credentials.
     */
    public boolean authenticate(final String username, final char[] password) {
        if (configFileLocation == null || username == null) {
            return false;
        }

        final String strPassword = new String(password);

        try {
            final UsernamePassword user = findUser(username);
            if (user == null) {
                LOGGER.error("Authentication failed for {}, unknown user", username);
                return false;
            }

            return authenticateUser(user, strPassword, username);
        } catch (final JsonReaderException ex) {
            LOGGER.error("Failed to read configuration file", ex);
            return false;
        }
    }

    /**
     * Find a user by username in the configuration.
     */
    private UsernamePassword findUser(final String username) throws JsonReaderException {
        final List<UsernamePassword> usernamePasswords = jsonReader.read();
        for (final UsernamePassword usernamePassword : usernamePasswords) {
            if (username.equals(usernamePassword.name())) {
                return usernamePassword;
            }
        }
        return null;
    }

    /**
     * Authenticate a user using either SCRAM credentials or plaintext password.
     */
    private boolean authenticateUser(final UsernamePassword user, final String password, final String username) {
        // Try SCRAM credentials first
        if (user.scramCredentials() != null && !user.scramCredentials().isEmpty()) {
            return authenticateWithScramCredentials(user, password, username);
        }

        // Fall back to plaintext password
        return authenticateWithPlaintextPassword(user, password, username);
    }

    /**
     * Authenticate using pre-computed SCRAM credentials.
     */
    private boolean authenticateWithScramCredentials(final UsernamePassword user,
                                                     final String password,
                                                     final String username) {
        final Map.Entry<String, UsernamePassword.ScramCredentialEntry> entry =
            user.scramCredentials().entrySet().iterator().next();
        final String mechanism = entry.getKey();
        final UsernamePassword.ScramCredentialEntry credEntry = entry.getValue();

        if (verifyPasswordAgainstScramCredential(password, mechanism, credEntry)) {
            LOGGER.debug("Authentication successful for {} using SCRAM credentials ({})", username, mechanism);
            return true;
        }

        LOGGER.error("Authentication failed for {}, invalid password using SCRAM credentials", username);
        return false;
    }

    /**
     * Authenticate using plaintext password comparison.
     */
    private boolean authenticateWithPlaintextPassword(final UsernamePassword user,
                                                      final String password,
                                                      final String username) {
        final String storedPassword = user.password();
        if (storedPassword == null) {
            LOGGER.error("Authentication failed for {}, no password or scram_credentials set", username);
            return false;
        }

        if (storedPassword.equals(password)) {
            LOGGER.debug("Authentication successful for {} using plaintext password", username);
            return true;
        }

        LOGGER.error("Authentication failed for {}, invalid password", username);
        return false;
    }

    /**
     * Verify a plaintext password against a pre-computed SCRAM credential.
     */
    private boolean verifyPasswordAgainstScramCredential(final String password,
                                                         final String mechanismName,
                                                         final UsernamePassword.ScramCredentialEntry credEntry) {
        try {
            // Get the SCRAM mechanism
            final ScramMechanism mechanism = ScramMechanism.forMechanismName(mechanismName);
            if (mechanism == null) {
                LOGGER.warn("Unsupported SCRAM mechanism for PLAIN authentication: {}", mechanismName);
                return false;
            }

            // Decode stored credential
            final byte[] storedSalt = Base64.getDecoder().decode(credEntry.salt());
            final byte[] storedServerKey = Base64.getDecoder().decode(credEntry.serverKey());
            final int iterations = credEntry.iterations();

            // Use ScramFormatter to generate credentials from the password
            final ScramFormatter formatter = new ScramFormatter(mechanism);
            final byte[] saltedPassword = formatter.saltedPassword(password, storedSalt, iterations);
            final byte[] generatedServerKey = formatter.serverKey(saltedPassword);

            // Compare the server key from the generated credential with the stored one
            return Arrays.equals(generatedServerKey, storedServerKey);

        } catch (final IllegalArgumentException e) {
            LOGGER.error("Failed to decode SCRAM credentials", e);
            return false;
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("Failed to verify password against SCRAM credentials", e);
            return false;
        } catch (final InvalidKeyException e) {
            LOGGER.error("Failed to verify password against SCRAM credentials", e);
            return false;
        }
    }

    @Override
    public void close() throws KafkaException {
    }
}
