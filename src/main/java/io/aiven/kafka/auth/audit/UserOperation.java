/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.util.Objects;

import kafka.security.auth.Operation;
import kafka.security.auth.Resource;

public class UserOperation {

    public final Operation operation;

    public final Resource resource;

    public final boolean hasAccess;

    public UserOperation(final Operation operation,
                         final Resource resource,
                         final boolean hasAccess) {
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
