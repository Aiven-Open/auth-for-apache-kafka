/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.audit;

import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

class UserActivity {

    public final ZonedDateTime activeSince;

    public final Set<UserOperation> operations;

    public UserActivity() {
        this.activeSince = ZonedDateTime.now();
        this.operations = new HashSet<>();
    }

    public void addOperation(final UserOperation userOperation) {
        operations.add(userOperation);
    }

    public boolean hasOperations() {
        return !operations.isEmpty();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserActivity)) {
            return false;
        }
        final UserActivity that = (UserActivity) o;
        return Objects.equals(activeSince, that.activeSince)
            && Objects.equals(operations, that.operations);
    }

    @Override
    public int hashCode() {
        return Objects.hash(activeSince, operations);
    }
}
