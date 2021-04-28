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

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

class UserActivity {
    public final ZonedDateTime activeSince;

    /**
     * Ordered in the order the order the operations are added.
     */
    public final List<UserOperation> operations;

    public UserActivity() {
        this(ZonedDateTime.now());
    }

    public UserActivity(final ZonedDateTime activeSince) {
        this.activeSince = activeSince;
        this.operations = new ArrayList<>();
    }

    public void addOperation(final UserOperation userOperation) {
        if (!operations.contains(userOperation)) {
            operations.add(userOperation);
        }
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
