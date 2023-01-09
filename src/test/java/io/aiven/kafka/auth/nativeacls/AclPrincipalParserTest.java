/*
 * Copyright 2023 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth.nativeacls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

public class AclPrincipalParserTest {

    @Test
    public final void parseSinglePrincipal() {
        assertThat(AclPrincipalParser.parse("User", "^username$"))
            .containsExactly("User:username");
    }

    @ParameterizedTest
    @ValueSource(strings = {"(.*)", "^(username|(.*))$"})
    public final void parseWildcardPrincipal(final String value) {
        assertThat(AclPrincipalParser.parse("User", value))
            .containsExactly("User:*");
    }

    @Test
    public final void parseMultipleUsers() {
        assertThat(AclPrincipalParser.parse("User", "^(user1|user2)$"))
            .containsExactly("User:user1", "User:user2");
    }

    @Test
    public final void parseNullPrincipal() {
        assertThat(AclPrincipalParser.parse("User", null))
            .isEmpty();
    }

    @Test
    public final void parseNullPrincipalType() {
        assertThat(AclPrincipalParser.parse(null, "^username$"))
            .isEmpty();
    }

}
