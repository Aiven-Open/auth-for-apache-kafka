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

import kafka.security.auth.Operation;
import kafka.security.auth.Resource;
import org.slf4j.Logger;

public class UserOperationsActivityAuditor extends Auditor {

    public UserOperationsActivityAuditor() {
    }

    protected UserOperationsActivityAuditor(final Logger logger) {
        super(logger);
    }

    @Override
    protected UserActivity onUserActivity(final UserActivity userActivity,
                                          final Operation operation,
                                          final Resource resource,
                                          final Boolean hasAccess) {
        userActivity.addOperation(new UserOperation(operation, resource, hasAccess));
        return userActivity;
    }

}
