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

import java.util.Map;

import com.google.gson.annotations.SerializedName;

public final class UsernamePassword {

    @SerializedName("username")
    private final String name;

    @SerializedName("password")
    private final String password;

    @SerializedName("scram_credentials")
    private final Map<String, ScramCredentialEntry> scramCredentials;

    public UsernamePassword(final String name, final String password) {
        this(name, password, null);
    }

    public UsernamePassword(final String name,
                           final String password,
                           final Map<String, ScramCredentialEntry> scramCredentials) {
        this.name = name;
        this.password = password;
        this.scramCredentials = scramCredentials;
    }

    public String name() {
        return name;
    }

    public String password() {
        return password;
    }

    public Map<String, ScramCredentialEntry> scramCredentials() {
        return scramCredentials;
    }

    public static final class ScramCredentialEntry {
        @SerializedName("salt")
        private final String salt;

        @SerializedName("stored_key")
        private final String storedKey;

        @SerializedName("server_key")
        private final String serverKey;

        @SerializedName("iterations")
        private final int iterations;

        public ScramCredentialEntry(final String salt,
                                   final String storedKey,
                                   final String serverKey,
                                   final int iterations) {
            this.salt = salt;
            this.storedKey = storedKey;
            this.serverKey = serverKey;
            this.iterations = iterations;
        }

        public String salt() {
            return salt;
        }

        public String storedKey() {
            return storedKey;
        }

        public String serverKey() {
            return serverKey;
        }

        public int iterations() {
            return iterations;
        }
    }

}
