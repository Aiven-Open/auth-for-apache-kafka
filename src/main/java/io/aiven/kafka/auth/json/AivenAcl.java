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

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.kafka.common.acl.AclOperation;

import io.aiven.kafka.auth.nameformatters.LegacyOperationNameFormatter;
import io.aiven.kafka.auth.utils.ResourceLiteralWildcardMatcher;

import com.google.gson.annotations.SerializedName;

public class AivenAcl {

    private static final String WILDCARD_HOST = "*";

    @SerializedName("principal_type")
    public final String principalType;

    @SerializedName("principal")
    public final Pattern principalRe;

    @SerializedName("operation")
    public final Pattern operationRe;

    public final List<AclOperationType> operations;

    @SerializedName("resource")
    public final Pattern resourceRe;

    @SerializedName("resource_pattern")
    public final String resourceRePattern;

    @SerializedName("resource_literal")
    public final String resourceLiteral;

    @SerializedName("resource_prefix")
    public final String resourcePrefix;

    @SerializedName("permission_type")
    private final AclPermissionType permissionType;

    @SerializedName("host")
    private final String hostMatcher;

    private final boolean hidden;

    public AivenAcl(
        final String principalType,
        final String principal,
        final String host,
        final String operation,
        final String resource,
        final String resourcePattern,
        final String resourceLiteral,
        final String resourcePrefix,
        final AclPermissionType permissionType,
        final boolean hidden
    ) {
        this.principalType = principalType;
        this.principalRe = Pattern.compile(principal);
        this.hostMatcher = host;
        this.operationRe = Pattern.compile(operation);
        this.operations = null;
        this.resourceRe = Objects.nonNull(resource) ? Pattern.compile(resource) : null;
        this.resourceRePattern = resourcePattern;
        this.resourceLiteral = resourceLiteral;
        this.resourcePrefix = resourcePrefix;
        this.permissionType = Objects.requireNonNullElse(permissionType, AclPermissionType.ALLOW);
        this.hidden = hidden;
    }

    public AivenAcl(
        final String principalType,
        final String principal,
        final String host,
        final List<AclOperationType> operations,
        final String resource,
        final String resourcePattern,
        final String resourceLiteral,
        final String resourcePrefix,
        final AclPermissionType permissionType,
        final boolean hidden
    ) {
        this.principalType = principalType;
        this.principalRe = Pattern.compile(principal);
        this.hostMatcher = host;
        this.operationRe = null;
        this.operations = operations;
        this.resourceRe = Objects.nonNull(resource) ? Pattern.compile(resource) : null;
        this.resourceRePattern = resourcePattern;
        this.resourceLiteral = resourceLiteral;
        this.resourcePrefix = resourcePrefix;
        this.permissionType = Objects.requireNonNullElse(permissionType, AclPermissionType.ALLOW);
        this.hidden = hidden;
    }

    public AclPermissionType getPermissionType() {
        // Gson does not call the constructor, and the default deserializer will set `this.permissionType` to null
        // if `permission_type` is not included in the json to be deserialized.
        // Therefore, this method should be the only way to correctly retrieve the permission type.
        // In order to fix this, a custom deserializer for `AivenAcl` should be implemented.
        return permissionType == null ? AclPermissionType.ALLOW : permissionType;
    }

    public String getHostMatcher() {
        // Same thing as getPermissionType(), host matching has been added later, and to be backward compatible
        // we consider a missing "host" field in the ACL json the same as WILDCARD_HOST ("*")
        return hostMatcher == null ? WILDCARD_HOST : hostMatcher;
    }

    /**
     * Check if request matches this rule.
     */
    public Boolean match(final String principalType,
                            final String principal,
                            final String host,
                            final AclOperation operation,
                            final String resource) {
        if (this.principalType == null || this.principalType.equals(principalType)) {
            final Matcher mp = this.principalRe.matcher(principal);
            return mp.find() && this.matchOperation(operation) && this.hostMatch(host)
                    && this.resourceMatch(resource, mp);
        }
        return false;
    }

    /* Some operations implicitly allow describe operation, but with allow rules only */
    private static final Set<AclOperation> IMPLIES_DESCRIBE = Collections.unmodifiableSet(
        EnumSet.of(AclOperation.DESCRIBE, AclOperation.READ, AclOperation.WRITE,
            AclOperation.DELETE, AclOperation.ALTER));

    private static final Set<AclOperation> IMPLIES_DESCRIBE_CONFIGS = Collections.unmodifiableSet(
        EnumSet.of(AclOperation.DESCRIBE_CONFIGS, AclOperation.ALTER_CONFIGS));


    private boolean matchOperation(final AclOperation operation) {
        if (this.operations != null) {
            for (final var mo : this.operations) {
                if (matchSingleOperation(operation, mo)) {
                    return true;
                }
            }
            return false;
        } else {
            final Matcher mo = this.operationRe.matcher(LegacyOperationNameFormatter.format(operation));
            return mo.find();
        }
    }

    private boolean matchSingleOperation(final AclOperation operation, final AclOperationType mo) {
        if (mo.nativeType == AclOperation.ALL) {
            return true;
        } else if (getPermissionType() == AclPermissionType.ALLOW) {
            switch (operation) {
                case DESCRIBE:
                    if (IMPLIES_DESCRIBE.contains(mo.nativeType)) {
                        return true;
                    }
                    break;
                case DESCRIBE_CONFIGS:
                    if (IMPLIES_DESCRIBE_CONFIGS.contains(mo.nativeType)) {
                        return true;
                    }
                    break;
                default:
                    if (operation == mo.nativeType) {
                        return true;
                    }
            }
        } else {
            if (operation == mo.nativeType) {
                return true;
            }
        }
        return false;
    }

    private boolean hostMatch(final String host) {
        return getHostMatcher().equals(WILDCARD_HOST)
            || getHostMatcher().equals(host);
    }

    private boolean resourceMatch(final String resource, final Matcher principalBackreference) {
        if (this.resourceRe != null) {
            return this.resourceRe.matcher(resource).find();
        } else if (this.resourceRePattern != null) {
            final String resourceReStr = principalBackreference.replaceAll(this.resourceRePattern);
            final Pattern resourceRe = Pattern.compile(resourceReStr);
            return resourceRe.matcher(resource).find();
        } else if (this.resourceLiteral != null) {
            return ResourceLiteralWildcardMatcher.match(this.resourceLiteral, resource)
                || this.resourceLiteral.equals(resource);
        } else if (this.resourcePrefix != null) {
            return resource != null && resource.startsWith(this.resourcePrefix);
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
        return equalsPrincipal(aivenAcl)
            && getHostMatcher().equals(aivenAcl.getHostMatcher())
            && comparePattern(operationRe, aivenAcl.operationRe)
            && equalsResource(aivenAcl)
            && getPermissionType() == aivenAcl.getPermissionType() // always compare permission type using getter
            && hidden == aivenAcl.hidden;
    }

    private boolean equalsPrincipal(final AivenAcl aivenAcl) {
        return Objects.equals(principalType, aivenAcl.principalType)
            && comparePattern(principalRe, aivenAcl.principalRe);
    }

    private boolean equalsResource(final AivenAcl aivenAcl) {
        return comparePattern(resourceRe, aivenAcl.resourceRe)
            && Objects.equals(resourceRePattern, aivenAcl.resourceRePattern)
            && Objects.equals(resourceLiteral, aivenAcl.resourceLiteral)
            && Objects.equals(resourcePrefix, aivenAcl.resourcePrefix);
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
            principalType, principalRe, hostMatcher, operationRe, operations, resourceRe,
            resourceRePattern, resourceLiteral, resourcePrefix, getPermissionType()
        );
    }

    @Override
    public String toString() {
        return "AivenAcl{"
                + "principalType='" + principalType
                + "', principalRe=" + principalRe
                + ", operationRe=" + operationRe
                + ", resource='" + getResourceString()
                + "', permissionType=" + getPermissionType()
                + ", hostMatcher='" + getHostMatcher()
                + ", hidden=" + hidden
                + "'}";
    }

    private String getResourceString() {
        if (resourceRe != null) {
            return resourceRe.toString();
        } else if (resourceRePattern != null) {
            return resourceRePattern;
        } else if (resourceLiteral != null) {
            return resourceLiteral + " (LITERAL)";
        } else {
            return resourcePrefix + " (PREFIXED)";
        }
    }

    public boolean isHidden() {
        return hidden;
    }
}
