/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
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
