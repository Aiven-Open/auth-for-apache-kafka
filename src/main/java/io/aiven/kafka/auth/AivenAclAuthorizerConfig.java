/*
 * Copyright 2019 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth;

import java.io.File;
import java.util.Map;

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigDef;

import io.aiven.kafka.auth.audit.AuditorAPI;
import io.aiven.kafka.auth.audit.NoAuditor;

public final class AivenAclAuthorizerConfig extends AbstractConfig {
    private static final String CONFIGURATION_CONF = "aiven.acl.authorizer.configuration";
    private static final String AUDITOR_CLASS_NAME_CONF = "aiven.acl.authorizer.auditor.class.name";
    private static final String LOG_DENIALS_CONF = "aiven.acl.authorizer.log.denials";
    private static final String CONFIG_REFRESH_CONF = "aiven.acl.authorizer.config.refresh.interval";
    private static final String LIST_ACLS_ENABLED_CONF = "aiven.acl.authorizer.list.acls.enabled";

    public AivenAclAuthorizerConfig(final Map<?, ?> originals) {
        super(configDef(), originals);
    }

    public static ConfigDef configDef() {
        return new ConfigDef()
            .define(
                CONFIGURATION_CONF,
                ConfigDef.Type.STRING,
                ConfigDef.NO_DEFAULT_VALUE,
                ConfigDef.Importance.HIGH,
                "The path to the configuration file"
            ).define(
                AUDITOR_CLASS_NAME_CONF,
                ConfigDef.Type.CLASS,
                NoAuditor.class,
                ConfigDef.Importance.MEDIUM,
                "The auditor class fully qualified name"
            ).define(
                LOG_DENIALS_CONF,
                ConfigDef.Type.BOOLEAN,
                true,
                ConfigDef.Importance.LOW,
                "Whether to log denials on INFO level"
            ).define(
                CONFIG_REFRESH_CONF,
                ConfigDef.Type.INT,
                10_000,
                ConfigDef.Importance.LOW,
                "The interval between ACL reloads"
            ).define(
                LIST_ACLS_ENABLED_CONF,
                ConfigDef.Type.BOOLEAN,
                true,
                ConfigDef.Importance.LOW,
                "Whether to allow listing ACLs"
            );
    }

    public File getConfigFile() {
        return new File(getString(CONFIGURATION_CONF));
    }

    public AuditorAPI getAuditor() {
        return getConfiguredInstance(AUDITOR_CLASS_NAME_CONF, AuditorAPI.class);
    }

    public boolean logDenials() {
        return getBoolean(LOG_DENIALS_CONF);
    }

    public int configRefreshInterval() {
        return getInt(CONFIG_REFRESH_CONF);
    }

    public boolean listAclsEnabled() {
        return getBoolean(LIST_ACLS_ENABLED_CONF);
    }
}
