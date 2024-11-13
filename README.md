# Aiven Authentication and Authorization Plugins for Apache Kafka®

## AivenAclAuthorizer

Aiven ACL authorizer. Implements ACL controls using JSON configuration file.
Config file is watched for modifications and reloaded as necessary.

### AivenAclEntry

Class implementing a single ACL entry verification. Principal and
resource are expressed as regular expressions.

Alternatively to straight regular expression for resource, AivenAclEntry can
be given a resource pattern with back references to principal regex, a literal
match or a prefixed match. The first is used internally in Aiven to map project
id from certificate subject into project specific management topics. We can thus
avoid encoding separate rules for each project. Literal and prefixed matchers
work as defined in the Apache Kafka documentation. Only one resource matcher can be
specified per acl.

Operations can be expressed as a list of operation names, or in deprecated mode
as regular expression in `operation` field.  If both are defined, `operations`
takes precedence.  For operations listed with operation names, also implicit Decribe
is supported if Read, Write, Alter, or Delete is allowed, and implicit
DescribeConfigs if AlterConfigs is allowed.

Permission type allows to define the verification result in case of an ACL match.
By default, the permission type is `ALLOW`.

A specific ACL entry can be hidden from public listing by setting hidden flag.

### Example

    [
        {
            "operations": ["All"],
            "principal": (
                "^CN=(?<vmname>[a-z0-9-]+),OU=(?<nodeid>n[0-9]+),"
                "O=00000000-0000-a000-1000-(500000000005|a00000000001|b00000000001|d00000000001),ST=vm$"
            ),
            "principal_type": "Prune",
            "host": "*",
            "resource": "^(.*)$",
            "hidden": true
        },
        {
            "operations": ["Describe", "DescribeConfigs", "Read", "Write"],
            "operation": "^(Describe|DescribeConfigs|Read|Write)$",
            "principal": "^CN=(?<vmname>[a-z0-9-]+),OU=(?<nodeid>n[0-9]+),O=(?<projectid>[a-f0-9-]+),ST=vm$",
            "principal_type": "Prune",
            "host": "*",
            "resource_pattern": "^Topic:${projectid}-(.*),
            "permission_type": "DENY"
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

## Trademarks

Apache Kafka is either a registered trademark or a trademark of the Apache Software Foundation in the United States and/or other countries.
