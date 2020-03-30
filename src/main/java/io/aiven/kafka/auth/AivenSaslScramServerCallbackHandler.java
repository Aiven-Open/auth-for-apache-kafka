package io.aiven.kafka.auth;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
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

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AivenSaslScramServerCallbackHandler implements AuthenticateCallbackHandler {
    private static final Logger LOGGER =
        LoggerFactory.getLogger(AivenSaslScramServerCallbackHandler.class);
    private String configFileLocation;
    private String mechanismName;
    private int mechanismIterations;
    private ScramFormatter formatter;

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
        final File configFile = new File(configFileLocation);

        if (formatter == null) {
            LOGGER.error(
                "Authentication failed for {}, no credential formatter set for mechanism {}",
                username, mechanismName
            );
            return null;
        }

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
                        return null;
                    }
                    return formatter.generateCredential(storedPassword, mechanismIterations);
                }
            }
        } catch (final IOException | ParseException ex) {
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
