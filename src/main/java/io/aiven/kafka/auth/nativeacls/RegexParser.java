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
import java.util.stream.Collectors;

class RegexParser {

    // Visible for test
    /**
     * Parses a regex pattern into a list.
     * <br>
     * For example, <code>^(AAA|BBB|CCC)$</code> results in <code>List("AAA", "BBB", "CCC")</code>,
     * <code>^AAA$</code> results in <code>List("AAA")</code>. Unparsable strings results in {@code null}.
     */
    static List<String> parse(String pattern) {
        if (pattern == null) {
            return null;
        }

        // Remove regex pattern prefix and postfix.
        if (!pattern.startsWith("^")) {
            return null;
        }
        pattern = pattern.substring(1);
        if (pattern.startsWith("(")) {
            pattern = pattern.substring(1);
        }

        if (!pattern.endsWith("$")) {
            return null;
        }
        pattern = pattern.substring(0, pattern.length() - 1);
        if (pattern.endsWith(")")) {
            pattern = pattern.substring(0, pattern.length() - 1);
        }

        if (pattern.equals("^(.*)$")) {
            return null;
        }

        return Arrays.stream(pattern.split("\\|")).collect(Collectors.toList());
    }
}
