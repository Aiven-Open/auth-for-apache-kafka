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

import java.util.Map;

import kafka.network.RequestChannel;
import kafka.security.auth.Operation;
import kafka.security.auth.Resource;

public class NoAuditor extends Auditor {

    public NoAuditor() {
        super();
    }

    @Override
    protected UserActivity onUserActivity(final UserActivity userActivity,
                                          final Operation operation,
                                          final Resource resource,
                                          final Boolean hasAccess) {
        return userActivity;
    }

    @Override
    public void addActivity(final RequestChannel.Session session,
                            final Operation operation,
                            final Resource resource,
                            final Boolean hasAccess) {
    }

    @Override
    public void configure(final Map<String, ?> map) {
    }

    @Override
    public void stop() {
    }
}
