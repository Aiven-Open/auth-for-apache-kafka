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
import java.security.Principal;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;

abstract class UserActivity {

    public final Principal principal;

    public final ZonedDateTime activeSince;

    protected UserActivity(final Principal principal) {
        this(principal, ZonedDateTime.now());
    }

    protected UserActivity(final Principal principal, final ZonedDateTime activeSince) {
        this.principal = principal;
        this.activeSince = activeSince;
    }

    abstract void addOperation(final UserOperation userOperation);

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserActivity)) {
            return false;
        }
        final UserActivity that = (UserActivity) o;
        return Objects.equals(principal, that.principal);
    }

    @Override
    public int hashCode() {
        return Objects.hash(principal);
    }

    static final class UserActivityOperations extends UserActivity {

        public UserActivityOperations(final Principal principal) {
            super(principal);
        }

        public UserActivityOperations(final Principal principal, final ZonedDateTime activeSince) {
            super(principal, activeSince);
        }

        /**
         * Ordered in the order the order the operations are added.
         */
        public final Set<UserOperation> operations = new LinkedHashSet<>();

        @Override
        void addOperation(final UserOperation userOperation) {
            operations.add(userOperation);
        }

    }

    static final class UserActivityOperationsGropedByIP extends UserActivity {

        public UserActivityOperationsGropedByIP(final Principal principal) {
            super(principal);
        }

        public UserActivityOperationsGropedByIP(final Principal principal, final ZonedDateTime activeSince) {
            super(principal, activeSince);
        }

        public final Map<InetAddress, Set<UserOperation>> operations = new LinkedHashMap<>();

        @Override
        void addOperation(final UserOperation userOperation) {
            final BiFunction<InetAddress, Set<UserOperation>, Set<UserOperation>> resolveUserOperations = (ip, o) -> {
                final var ops =
                        Objects.isNull(o) ? new LinkedHashSet<UserOperation>() : o;
                ops.add(userOperation);
                return ops;
            };
            operations.compute(userOperation.sourceIp, resolveUserOperations::apply);
        }

    }

}
