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

import java.util.List;
import java.util.stream.Collectors;

import org.apache.kafka.common.acl.AclOperation;

import io.aiven.kafka.auth.nameformatters.OperationNameFormatter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class AclOperationsParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(AclOperationsParser.class);

    // Visible for test
    static Iterable<AclOperation> parse(final String operationPattern) {
        if (operationPattern == null) {
            return List.of();
        }

        if (operationPattern.equals("^.*$") || operationPattern.equals("^(.*)$")) {
            return List.of(
                AclOperation.ALL
            );
        }

        final List<String> parsedOperationList = RegexParser.parse(operationPattern);
        if (parsedOperationList == null) {
            LOGGER.debug("Nothing parsed from operation {}", operationPattern);
            return List.of();
        }
        return parsedOperationList.stream()
            .map(OperationNameFormatter::format)
            .filter(o -> o != AclOperation.UNKNOWN)
            .collect(Collectors.toList());
    }
}
