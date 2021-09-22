/*
 * Copyright 2020 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth.audit;

import java.net.InetAddress;
import java.util.Objects;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourcePattern;

public class UserOperation {

    public final InetAddress sourceIp;

    public final AclOperation operation;

    public final ResourcePattern resource;

    public final boolean hasAccess;

    public UserOperation(final AclOperation operation,
                         final ResourcePattern resource,
                         final boolean hasAccess) {
        this(null, operation, resource, hasAccess);
    }

    public UserOperation(final InetAddress sourceIp,
                         final AclOperation operation,
                         final ResourcePattern resource,
                         final boolean hasAccess) {
        this.sourceIp = sourceIp;
        this.operation = operation;
        this.resource = resource;
        this.hasAccess = hasAccess;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserOperation)) {
            return false;
        }
        final UserOperation that = (UserOperation) o;
        return hasAccess == that.hasAccess
                && Objects.equals(operation, that.operation)
                && Objects.equals(resource, that.resource);
    }

    @Override
    public int hashCode() {
        return Objects.hash(operation, resource, hasAccess);
    }

}
