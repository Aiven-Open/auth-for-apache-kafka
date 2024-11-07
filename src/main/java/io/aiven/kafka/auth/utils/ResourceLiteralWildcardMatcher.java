/*
 * Copyright 2024 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth.utils;

public class ResourceLiteralWildcardMatcher {
    // Here "pattern" is something like "Topic:topic-1" or "Topic:*", where the second form is the
    // wildcard matching. The wildcard match is a bit more difficult than comparing for just "*", because
    // the prefix must be compared with the one of "resource".
    public static boolean match(final String pattern, final String resource) {
        if (pattern == null || resource == null) {
            return false;
        }
        final int matchLength = Math.min(pattern.length(), resource.length());
        for (int i = 0; i < matchLength; i++) {
            if (pattern.charAt(i) != resource.charAt(i)) {
                return false;
            }
            if (pattern.charAt(i) == ':') {
                return pattern.length() > i + 1 && pattern.charAt(i + 1) == '*';
            }
        }
        return false;
    }
}
