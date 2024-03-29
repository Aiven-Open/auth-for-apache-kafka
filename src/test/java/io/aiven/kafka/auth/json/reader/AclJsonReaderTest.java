/*
 * Copyright 2023 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth.json.reader;

import java.io.File;

import io.aiven.kafka.auth.json.AclPermissionType;
import io.aiven.kafka.auth.json.AivenAcl;

import com.google.gson.JsonParseException;
import org.junit.jupiter.api.Test;


import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AclJsonReaderTest {

    @Test
    public final void parseAcls() {
        final var path = new File(this.getClass().getResource("/acls_full.json").getPath()).toPath();
        final var jsonReader = new AclJsonReader(path);
        final var acls = jsonReader.read();
        assertThat(acls).containsExactly(
            new AivenAcl("User", "^pass-3$", "^Read$", "^Topic:denied$", null, AclPermissionType.DENY),
            new AivenAcl("User", "^pass-0$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-1$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-2$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-3$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-4$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-5$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-6$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-7$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-8$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-9$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-10$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-11$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl("User", "^pass-12$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl(null, "^pass-notype$", "^Read$", "^Topic:(.*)$", null, AclPermissionType.ALLOW),
            new AivenAcl(
                "User", "^pass-resource-pattern$", "^Read$", null, "^Topic:${projectid}-(.*)", AclPermissionType.ALLOW
            )
        );
    }

    @Test
    public final void parseDenyAcl() {
        final var path = new File(this.getClass().getResource("/test_parse_acl_type.json").getPath()).toPath();
        final var jsonReader = new AclJsonReader(path);
        final var acls = jsonReader.read();
        final var allowAcl = new AivenAcl(
            "User",
            "^allow$",
            "^Read$",
            "^(.*)$",
            null,
            AclPermissionType.ALLOW
        );
        final var denyAcl = new AivenAcl(
            "User",
            "^deny$",
            "^Read$",
            "^(.*)$",
            null,
            AclPermissionType.DENY
        );
        assertThat(acls).containsExactly(allowAcl, allowAcl, allowAcl, denyAcl, denyAcl);
    }

    @Test
    public final void parseWrong() {
        final var path = new File(this.getClass().getResource("/acl_wrong_permission_type.json").getPath()).toPath();
        final var jsonReader = new AclJsonReader(path);
        assertThrows(JsonParseException.class, jsonReader::read);
    }

}
