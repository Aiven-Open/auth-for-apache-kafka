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
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.plain.PlainLoginModule;

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
     */
    public boolean authenticate(final String username, final char[] password) {
        if (configFileLocation == null || username == null) {
            return false;
        } else {
            final String strPassword = new String(password);

            try {
                final List<UsernamePassword> usernamePasswords = jsonReader.read();
                for (final UsernamePassword usernamePassword : usernamePasswords) {
                    if (username.equals(usernamePassword.name())) {
                        final String storedPassword = usernamePassword.password();
                        if (storedPassword == null) {
                            LOGGER.error("Authentication failed for {}, no password set", username);
                            return false;
                        } else if (storedPassword.equals(strPassword)) {
                            LOGGER.debug("Authentication successful for {}", username);
                            return true;
                        } else {
                            LOGGER.error("Authentication failed for {}, invalid password", username);
                            return false;
                        }
                    }
                }
            } catch (final JsonReaderException ex) {
                LOGGER.error("Failed to read configuration file", ex);
                return false;
            }
        }

        LOGGER.error("Authentication failed for {}, unknown user", username);
        return false;
    }

    @Override
    public void close() throws KafkaException {
    }
}
