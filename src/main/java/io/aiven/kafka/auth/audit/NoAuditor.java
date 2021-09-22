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

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourcePattern;

import kafka.network.RequestChannel;

/**
 * A no-op {@link AuditorAPI}.
 */
public class NoAuditor implements AuditorAPI {

    public NoAuditor() {
        super();
    }

    @Override
    public void addActivity(final RequestChannel.Session session,
                            final AclOperation operation,
                            final ResourcePattern resource,
                            final boolean hasAccess) {
    }

    @Override
    public void configure(final Map<String, ?> map) {
    }

    @Override
    public void stop() {
    }
}
