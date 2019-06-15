package io.aiven.kafka.auth;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
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
  private static final Logger logger =
      LoggerFactory.getLogger(AivenSaslPlainServerCallbackHandler.class);
  private String configFileLocation;

  @Override
  public void configure(Map<String, ?> configs, String mechanism,
          List<AppConfigurationEntry> jaasConfigEntries) {
    configFileLocation = JaasContext.configEntryOption(
            jaasConfigEntries, "users.config", PlainLoginModule.class.getName());
    logger.info("Using configuration file {}", configFileLocation);
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    String username = null;
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback) {
        NameCallback nameCallback = (NameCallback) callback;
        username = nameCallback.getDefaultName();
      } else if (callback instanceof PlainAuthenticateCallback) {
        PlainAuthenticateCallback plainCallback = (PlainAuthenticateCallback) callback;
        boolean authenticated = authenticate(username, plainCallback.password());
        plainCallback.authenticated(authenticated);
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  /** Check whether the given username is found and whether password is valid. */
  public boolean authenticate(String username, char[] password) {
    if (configFileLocation == null || username == null) {
      return false;
    } else {
      File configFile = new File(configFileLocation);
      String strPassword = new String(password);

      JSONParser parser = new JSONParser();
      try {
        Object obj = parser.parse(new FileReader(configFile));
        JSONArray root = (JSONArray) obj;
        Iterator<JSONObject> iter = root.iterator();
        while (iter.hasNext()) {
          JSONObject node = iter.next();
          if (username.equals(node.get("username"))) {
            String storedPassword = (String)node.get("password");
            if (storedPassword == null) {
              logger.error("Authentication failed for {}, no password set", username);
              return false;
            } else if (storedPassword.equals(strPassword)) {
              logger.info("Authentication successful for {}", username);
              return true;
            } else {
              logger.error("Authentication failed for {}, invalid password", username);
              return false;
            }
          }
        }
      } catch (IOException | ParseException ex) {
        logger.error("Failed to read configuration file", ex);
        return false;
      }
    }

    logger.error("Authentication failed for {}, unknown user", username);
    return false;
  }

  @Override
  public void close() throws KafkaException {
  }
}
