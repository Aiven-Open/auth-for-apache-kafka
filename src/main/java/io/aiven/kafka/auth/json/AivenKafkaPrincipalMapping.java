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

package io.aiven.kafka.auth.json;

import java.util.regex.Pattern;

import org.apache.kafka.common.security.auth.KafkaPrincipal;

import com.google.gson.annotations.SerializedName;

public class AivenKafkaPrincipalMapping {
    @SerializedName("subject_matcher")
    private final Pattern subjectRegex;
    @SerializedName("principal_name")
    private final String principalName;
    @SerializedName("principal_type")
    private final String principalType;

    public AivenKafkaPrincipalMapping(final String subjectRegex,
                                      final String principalName,
                                      final String principalType) {
        this.subjectRegex = Pattern.compile(subjectRegex);
        this.principalName = principalName;
        this.principalType = principalType;
    }

    public static AivenKafkaPrincipalMapping forUnknownSslPrincipal() {
        return new EntryForUnknownSslPrincipal();
    }

    /**
     * Checks if {@code sslPrincipal} matches against the regex of this entry.
     */
    public boolean matches(final String sslPrincipal) {
        return subjectRegex.matcher(sslPrincipal).matches();
    }

    /**
     * Builds {@link KafkaPrincipal} that corresponds to {@code sslPrincipal}.
     *
     * <p>The method does not checks if the {@code sslPrincipal} matches the entry.
     * For this purpose, use {@link #matches(String)} first.
     */
    public KafkaPrincipal buildKafkaPrincipal(final String sslPrincipal) {

        final String principalType = (this.principalType != null)
            ? this.principalType : KafkaPrincipal.USER_TYPE;
        final String principalName = (this.principalName != null)
            ? this.principalName : sslPrincipal;
        return new KafkaPrincipal(principalType, principalName);
    }

    private static class EntryForUnknownSslPrincipal extends AivenKafkaPrincipalMapping {
        public EntryForUnknownSslPrincipal() {
            super("", "", "");
        }

        @Override
        public boolean matches(final String sslPrincipal) {
            return true;
        }

        @Override
        public KafkaPrincipal buildKafkaPrincipal(final String sslPrincipal) {
            return new KafkaPrincipal("Invalid", "UNKNOWN (" + sslPrincipal + ")");
        }
    }
}
