/** Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.util.regex.Pattern;
import org.apache.kafka.common.security.auth.KafkaPrincipal;

public class AivenKafkaPrincipalMappingEntry {
  private Pattern subjectRegex;
  private String principalName;
  private String principalType;

  /** Contructor. */
  public AivenKafkaPrincipalMappingEntry(String subjectRegex, String principalName,
          String principalType) {
    this.subjectRegex = Pattern.compile(subjectRegex);
    this.principalName = principalName;
    this.principalType = principalType;
  }

  /**
   * Checks if {@code sslPrincipal} matches against the regex of this entry.
   */
  boolean matches(String sslPrincipal) {
    return subjectRegex.matcher(sslPrincipal).matches();
  }

  /**
   * Builds {@link KafkaPrincipal} that corresponds to {@code sslPrincipal}.
   *
   * <p>The method does not checks if the {@code sslPrincipal} matches the entry.
   * For this purpose, use {@link #matches(String)} first.
   */
  KafkaPrincipal buildKafkaPrincipal(String sslPrincipal) {
    String principalType;
    String principalName;
    if (this.principalType != null) {
      principalType = this.principalType;
    } else {
      principalType = KafkaPrincipal.USER_TYPE;
    }

    if (this.principalName != null) {
      principalName = this.principalName;
    } else {
      principalName = sslPrincipal;
    }
    return new KafkaPrincipal(principalType, principalName);
  }

  public static AivenKafkaPrincipalMappingEntry forUnknownSslPrincipal() {
    return new EntryForUnknownSslPrincipal();
  }

  private static class EntryForUnknownSslPrincipal extends AivenKafkaPrincipalMappingEntry {
    public EntryForUnknownSslPrincipal() {
      super("", "", "");
    }

    @Override
    boolean matches(String sslPrincipal) {
      return true;
    }

    @Override
    KafkaPrincipal buildKafkaPrincipal(String sslPrincipal) {
      return new KafkaPrincipal("Invalid", "UNKNOWN (" + sslPrincipal + ")");
    }
  }
}
