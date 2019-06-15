# Aiven Kafka Authorization plugins

## AivenAclAuthorizer

Aiven ACL authorizer. Implements ACL controls using JSON configuration file.
Config file is watched for modifications and reloaded as necessary.

### AivenAclEntry

Class implementing a single ACL entry verification. Principal, operation and
resource are expressed as regular expressions.

Alternatively to straight regular expression for resource, AivenAclEntry can
be given a resource pattern with back references to principal regex. This is
used internally in Aiven to map project id from certificate subject into
project specific management topics. We can thus avoid encoding separate rules
for each project.

### Example

    [
        {
            "operation": "^(.*)$",
            "principal": (
                "^CN=(?<vmname>[a-z0-9-]+),OU=(?<nodeid>n[0-9]+),"
                "O=00000000-0000-a000-1000-(500000000005|a00000000001|b00000000001|d00000000001),ST=vm$"
            ),
            "principal_type": "Prune",
            "resource": "^(.*)$",
        },
        {
            "operation": "^(Describe|DescribeConfigs|Read|Write)$",
            "principal": "^CN=(?<vmname>[a-z0-9-]+),OU=(?<nodeid>n[0-9]+),O=(?<projectid>[a-f0-9-]+),ST=vm$",
            "principal_type": "Prune",
            "resource_pattern": "^Topic:${projectid}-(.*)",
        }
    ]

## AivenKafkaPrincipalBuilder

Maps SSL Certificates to username principals. This allows us to utilize the
same ACL rules regardless whether the authentication is done with SASL or
certificates.

Configuration is done via a JSON config file.

### AivenKafkaPrincipalMappingEntry

Class implementing a single mapping entry.

Takes a regular expression for capturing subject line.

Can be given optional principal argument to be used instead for the principal.
If not given, the original certificate subject is retained.

Optional principal type can be given. This is useful in e.g. segregating normal
users and system users into separate namespace.

### Example

    [
        {
            "subject_matcher": f"^CN=user,O=Aiven$",
            "principal_name": "username",
            "principal_type": "User",
        },
        {
            "subject_matcher": "^(.*),ST=service$",
            "principal_type": "Service",
        }
    ]
