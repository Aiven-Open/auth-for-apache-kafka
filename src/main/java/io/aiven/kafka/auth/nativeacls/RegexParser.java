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

import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

class RegexParser {

    private static final Pattern PARSER_PATTERN = Pattern.compile("(?<=^\\^)(.*?)(?=\\$$)");

    // Visible for test
    /**
     * Parses a regex pattern into a list.
     * <br>
     * For example, <code>^(AAA|BBB|CCC)$</code> results in <code>List("AAA", "BBB", "CCC")</code>,
     * <code>^AAA$</code> results in <code>List("AAA")</code>. Unparsable strings results in {@code null}.
     */
    static List<String> parse(final String pattern) {
        if (pattern == null) {
            return null;
        }

        final Matcher matcher = PARSER_PATTERN.matcher(pattern);
        if (!matcher.find() || matcher.groupCount() != 1) {
            return null;
        }

        String group = matcher.group(0);
        final int lastChar = group.length() - 1;
        if (group.charAt(0) == '(' && group.charAt(lastChar) == ')') {
            group = group.substring(1, lastChar);
        }
        return Arrays.stream(group.split("\\|"))
            .filter(Predicate.not(String::isBlank))
            .collect(Collectors.toList());
    }
}
