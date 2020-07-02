/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.io.File;
import java.util.Map;

import org.apache.kafka.common.config.AbstractConfig;
import org.apache.kafka.common.config.ConfigDef;

import io.aiven.kafka.auth.audit.Auditor;
import io.aiven.kafka.auth.audit.NoAuditor;

public final class AivenAclAuthorizerConfig extends AbstractConfig {
    private static final String CONFIGURATION_CONF = "aiven.acl.authorizer.configuration";
    private static final String AUDITOR_CLASS_NAME_CONF = "aiven.acl.authorizer.auditor.class.name";
    private static final String LOG_DENIALS_CONF = "aiven.acl.authorizer.log.denials";

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
            );
    }

    public final File getConfigFile() {
        return new File(getString(CONFIGURATION_CONF));
    }

    public final Auditor getAuditor() {
        return getConfiguredInstance(AUDITOR_CLASS_NAME_CONF, Auditor.class);
    }

    public final boolean logDenials() {
        return getBoolean(LOG_DENIALS_CONF);
    }
}
