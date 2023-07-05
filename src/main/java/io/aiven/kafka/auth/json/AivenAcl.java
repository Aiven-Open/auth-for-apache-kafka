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

public class AivenAcl {
    @SerializedName("principal_type")
    public final String principalType;

    @SerializedName("principal")
    public final Pattern principalRe;

    @SerializedName("operation")
    public final Pattern operationRe;

    @SerializedName("resource")
    public final Pattern resourceRe;

    @SerializedName("resource_pattern")
    public final String resourceRePattern;

    @SerializedName("permission_type")
    private final AclPermissionType permissionType;

    public AivenAcl(final String principalType,
                    final String principal,
                    final String operation,
                    final String resource,
                    final String resourcePattern,
                    final AclPermissionType permissionType) {
        this.principalType = principalType;
        this.principalRe = Pattern.compile(principal);
        this.operationRe = Pattern.compile(operation);
        this.resourceRe = Objects.nonNull(resource) ? Pattern.compile(resource) : null;
        this.resourceRePattern = resourcePattern;
        this.permissionType = Objects.requireNonNullElse(permissionType, AclPermissionType.ALLOW);
    }

    public AclPermissionType getPermissionType() {
        // Gson does not call the constructor, and the default deserializer will set `this.permissionType` to null
        // if `permission_type` is not included in the json to be deserialized.
        // Therefore, this method should be the only way to correctly retrieve the permission type.
        // In order to fix this, a custom deserializer for `AivenAcl` should be implemented.
        return permissionType == null ? AclPermissionType.ALLOW : permissionType;
    }

    /**
     * Check if request matches this rule.
     */
    public Boolean match(final String principalType,
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

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final AivenAcl aivenAcl = (AivenAcl) o;
        return Objects.equals(principalType, aivenAcl.principalType)
            && comparePattern(principalRe, aivenAcl.principalRe)
            && comparePattern(operationRe, aivenAcl.operationRe)
            && comparePattern(resourceRe, aivenAcl.resourceRe)
            && Objects.equals(resourceRePattern, aivenAcl.resourceRePattern)
            && getPermissionType() == aivenAcl.getPermissionType(); // always compare permission type using getter
    }

    private boolean comparePattern(final Pattern p1, final Pattern p2) {
        // this method should be used only for testing purposes, as it does not represent a complete
        // comparison of two Patterns.
        if (p1 == null && p2 == null) {
            return true;
        }
        if (p1 == null || p2 == null) {
            return false;
        }

        return p1.toString().equals(p2.toString());
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            principalType, principalRe, operationRe, resourceRe, resourceRePattern, getPermissionType()
        );
    }
}
