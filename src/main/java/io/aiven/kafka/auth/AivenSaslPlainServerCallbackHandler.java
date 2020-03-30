package io.aiven.kafka.auth;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.security.plain.PlainLoginModule;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AivenSaslPlainServerCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger LOGGER =
        LoggerFactory.getLogger(AivenSaslPlainServerCallbackHandler.class);
    private String configFileLocation;

    @Override
    public void configure(final Map<String, ?> configs,
                          final String mechanism,
                          final List<AppConfigurationEntry> jaasConfigEntries) {
        configFileLocation = JaasContext.configEntryOption(
            jaasConfigEntries, "users.config", PlainLoginModule.class.getName());
        LOGGER.info("Using configuration file {}", configFileLocation);
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
            final File configFile = new File(configFileLocation);
            final String strPassword = new String(password);

            final JSONParser parser = new JSONParser();
            try {
                final Object obj = parser.parse(new FileReader(configFile));
                final JSONArray root = (JSONArray) obj;
                final Iterator<JSONObject> iter = root.iterator();
                while (iter.hasNext()) {
                    final JSONObject node = iter.next();
                    if (username.equals(node.get("username"))) {
                        final String storedPassword = (String) node.get("password");
                        if (storedPassword == null) {
                            LOGGER.error("Authentication failed for {}, no password set", username);
                            return false;
                        } else if (storedPassword.equals(strPassword)) {
                            LOGGER.info("Authentication successful for {}", username);
                            return true;
                        } else {
                            LOGGER.error("Authentication failed for {}, invalid password", username);
                            return false;
                        }
                    }
                }
            } catch (final IOException | ParseException ex) {
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
