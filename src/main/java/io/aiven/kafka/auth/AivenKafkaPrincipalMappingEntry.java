/**
 * Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.util.regex.Pattern;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

public class AivenKafkaPrincipalMappingEntry {
    private final Pattern subjectRegex;
    private final String principalName;
    private final String principalType;

    /** Contructor. */
    public AivenKafkaPrincipalMappingEntry(final String subjectRegex,
                                           final String principalName,
                                           final String principalType) {
        this.subjectRegex = Pattern.compile(subjectRegex);
        this.principalName = principalName;
        this.principalType = principalType;
    }

    public static AivenKafkaPrincipalMappingEntry forUnknownSslPrincipal() {
        return new EntryForUnknownSslPrincipal();
    }

    /**
     * Checks if {@code sslPrincipal} matches against the regex of this entry.
     */
    boolean matches(final String sslPrincipal) {
        return subjectRegex.matcher(sslPrincipal).matches();
    }

    /**
     * Builds {@link KafkaPrincipal} that corresponds to {@code sslPrincipal}.
     *
     * <p>The method does not checks if the {@code sslPrincipal} matches the entry.
     * For this purpose, use {@link #matches(String)} first.
     */
    KafkaPrincipal buildKafkaPrincipal(final String sslPrincipal) {

        final String principalType = (this.principalType != null)
            ? this.principalType : KafkaPrincipal.USER_TYPE;
        final String principalName = (this.principalName != null)
            ? this.principalName : sslPrincipal;
        return new KafkaPrincipal(principalType, principalName);
    }

    private static class EntryForUnknownSslPrincipal extends AivenKafkaPrincipalMappingEntry {
        public EntryForUnknownSslPrincipal() {
            super("", "", "");
        }

        @Override
        boolean matches(final String sslPrincipal) {
            return true;
        }

        @Override
        KafkaPrincipal buildKafkaPrincipal(final String sslPrincipal) {
            return new KafkaPrincipal("Invalid", "UNKNOWN (" + sslPrincipal + ")");
        }
    }
}
