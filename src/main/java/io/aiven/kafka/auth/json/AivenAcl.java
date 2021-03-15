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

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.annotations.SerializedName;

public class  AivenAcl {
    @SerializedName("principal_type")
    private final String principalType;

    @SerializedName("principal")
    private final Pattern principalRe;

    @SerializedName("operation")
    private final Pattern operationRe;

    @SerializedName("resource")
    private final Pattern resourceRe;

    @SerializedName("resource_pattern")
    private final String resourceRePattern;

    public AivenAcl(final String principalType,
                    final String principal,
                    final String operation,
                    final String resource,
                    final String resourcePattern) {
        this.principalType = principalType;
        this.principalRe = Pattern.compile(principal);
        this.operationRe = Pattern.compile(operation);
        this.resourceRe = Objects.nonNull(resource)
            ? Pattern.compile(resource) : null;
        this.resourceRePattern = resourcePattern;
    }

    /**
     * Check if request matches this rule.
     */
    public Boolean check(final String principalType,
                         final String principal,
                         final String operation,
                         final String resource) {
        if (this.principalType == null || this.principalType.equals(principalType)) {
            final Matcher mp = this.principalRe.matcher(principal);
            final Matcher mo = this.operationRe.matcher(operation);
            if (mp.find() && mo.find()) {
                Matcher mr = null;
                if (this.resourceRe != null) {
                    mr = this.resourceRe.matcher(resource);
                } else if (this.resourceRePattern != null) {
                    final String resourceReStr = mp.replaceAll(this.resourceRePattern);
                    final Pattern resourceRe = Pattern.compile(resourceReStr);
                    mr = resourceRe.matcher(resource);
                }
                if (mr != null && mr.find()) {
                    return true;
                }
            }
        }
        return false;
    }
}
