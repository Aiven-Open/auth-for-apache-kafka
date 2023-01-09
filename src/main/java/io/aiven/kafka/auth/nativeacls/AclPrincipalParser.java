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

import java.util.List;
import java.util.stream.Collectors;

class AclPrincipalParser {
    // Visible for test
    static List<String> parse(final String principalType, final String principalPattern) {
        if (principalType == null || principalPattern == null) {
            return List.of();
        }
        if (principalPattern.contains(".*")) {
            return List.of(principalType + ":*");
        }
        List<String> principals = RegexParser.parse(principalPattern);
        if (principals == null) {
            principals = List.of(principalPattern);
        }
        return principals.stream()
            .map(p -> principalType + ":" + p)
            .collect(Collectors.toList());
    }

}
