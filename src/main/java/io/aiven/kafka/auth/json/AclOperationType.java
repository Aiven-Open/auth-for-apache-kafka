/*
 * Copyright 2024 Aiven Oy https://aiven.io
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

public enum AclOperationType {
    Unknown(org.apache.kafka.common.acl.AclOperation.UNKNOWN),
    All(org.apache.kafka.common.acl.AclOperation.ALL),
    Read(org.apache.kafka.common.acl.AclOperation.READ),
    Write(org.apache.kafka.common.acl.AclOperation.WRITE),
    Create(org.apache.kafka.common.acl.AclOperation.CREATE),
    Delete(org.apache.kafka.common.acl.AclOperation.DELETE),
    Alter(org.apache.kafka.common.acl.AclOperation.ALTER),
    Describe(org.apache.kafka.common.acl.AclOperation.DESCRIBE),
    ClusterAction(org.apache.kafka.common.acl.AclOperation.CLUSTER_ACTION),
    DescribeConfigs(org.apache.kafka.common.acl.AclOperation.DESCRIBE_CONFIGS),
    AlterConfigs(org.apache.kafka.common.acl.AclOperation.ALTER_CONFIGS),
    IdempotentWrite(org.apache.kafka.common.acl.AclOperation.IDEMPOTENT_WRITE),
    CreateTokens(org.apache.kafka.common.acl.AclOperation.CREATE_TOKENS),
    DescribeTokens(org.apache.kafka.common.acl.AclOperation.DESCRIBE_TOKENS);

    public final org.apache.kafka.common.acl.AclOperation nativeType;

    AclOperationType(final org.apache.kafka.common.acl.AclOperation nativeType) {
        this.nativeType = nativeType;
    }
}
