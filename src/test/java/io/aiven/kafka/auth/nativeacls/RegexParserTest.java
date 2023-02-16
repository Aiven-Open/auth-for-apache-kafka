/*
 * Copyright 2022 Aiven Oy https://aiven.io
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

public class RegexParserTest {
    @Test
    public final void parseRegexListSingle() {
        assertThat(RegexParser.parse("^AAA$"))
            .containsExactly("AAA");
    }

    @Test
    public final void parseRegexListSingleWithParens() {
        assertThat(RegexParser.parse("^(AAA)$"))
            .containsExactly("AAA");
    }

    @Test
    public final void parseParenthesis() {
        assertThat(RegexParser.parse("^qwe)$"))
            .containsExactly("qwe)");
    }

    @Test
    public final void parseNestedRegex() {
        assertThat(RegexParser.parse("^(AAA|^(BB)$)$"))
            .containsExactly("AAA", "^(BB)$");
    }

    @Test
    public final void parseRegexListMultiple() {
        assertThat(RegexParser.parse("^(AAA|BBB|CCC|DDD)$"))
            .containsExactly("AAA", "BBB", "CCC", "DDD");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "^(AAA|BBB|CCC|DDD)",
        "(AAA|BBB|CCC|DDD)$",
        "^(AAA|BBB|CCC|DDD",
        "AAA|BBB|CCC|DDD)$"
    })
    public final void parseRegexListInvalid(final String pattern) {
        assertThat(RegexParser.parse(pattern))
            .isNull();
    }
}
