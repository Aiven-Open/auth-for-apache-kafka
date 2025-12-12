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

## SASL Authentication Handlers

`AivenSaslPlainServerCallbackHandler` implements SASL/PLAIN authentication.

`AivenSaslScramServerCallbackHandler` implements SASL/SCRAM authentication using SCRAM-SHA-256 and SCRAM-SHA-512 methods.

#### Configuration

The handler is configured via the `users.config` JAAS option pointing to a credentials file in `server.properties`:

```
sasl.enabled.mechanisms=PLAIN,SCRAM-SHA-256,SCRAM-SHA-512

listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required users.config="credentials.json";
listener.name.sasl_plaintext.plain.sasl.server.callback.handler.class=io.aiven.kafka.auth.AivenSaslPlainServerCallbackHandler
listener.name.sasl_plaintext.scram-sha-256.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required users.config="credentials.json";
listener.name.sasl_plaintext.scram-sha-256.sasl.server.callback.handler.class=io.aiven.kafka.auth.AivenSaslScramServerCallbackHandler
listener.name.sasl_plaintext.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required users.config="credentials.json";
listener.name.sasl_plaintext.scram-sha-512.sasl.server.callback.handler.class=io.aiven.kafka.auth.AivenSaslScramServerCallbackHandler
```

#### JSON Format

```json
[
  {
    "username": "alice",
    "scram_credentials": {
      "SCRAM-SHA-256": {
        "salt": "base64-encoded-salt",
        "stored_key": "base64-encoded-stored-key",
        "server_key": "base64-encoded-server-key",
        "iterations": 4096
      },
      "SCRAM-SHA-512": {
        "salt": "base64-encoded-salt",
        "stored_key": "base64-encoded-stored-key",
        "server_key": "base64-encoded-server-key",
        "iterations": 4096
      }
    }
  },
  {
    "username": "bob",
    "password": "plaintextpassword"
  }
]
```

**Fields:**
- `username` (required): The username for authentication
- `scram_credentials` (optional): Salted, iterated hash format of SCRAM credentials
- `password` (optional): Plaintext password for runtime credential generation

**SCRAM Credentials Structure:**
The `scram_credentials` field is a map where:
- **Key**: SCRAM mechanism name (e.g., `"SCRAM-SHA-256"`, `"SCRAM-SHA-512"`)
- **Value**: Credential object containing:
  - `salt`: Base64-encoded random salt used in password hashing
  - `stored_key`: Base64-encoded stored key derived from client key for authentication verification
  - `server_key`: Base64-encoded server key derived from salted password for server authentication
  - `iterations`: Number of PBKDF2 iterations used in key derivation (typically 4096)

#### Generating Salted and Hashed SCRAM Credentials

Salted and iterated hashed credentials can be generated using the provided Python utility. The tool generates credentials for both SCRAM-SHA-256 and SCRAM-SHA-512:

```bash
python utils/scram_credential_generator.py mysecret
{
  "SCRAM-SHA-256": {
    "salt": "vqmwUqVOYjNoBL2H00xvcvnfD/jxps+9v0FCgQdjaXk=",
    "stored_key": "n9C6ypVqZMoYaBLgtuP4oZIfaMkAl53SiTB4WOikdKM=",
    "server_key": "H5TKKDDeoWBm6vyEqAIlCq0H0RGQ2AN4IylFHDvt9tk=",
    "iterations": 4096
  },
  "SCRAM-SHA-512": {
    "salt": "g4g/kjDiAQLKXBvDupovgVOShDRWX83V8bFm1n6yiU4=",
    "stored_key": "T1WFWb3T3N7DuhR2KsrHI4Emx/+EzK/daMh0/noYUl/By+vI0vUOWVte4Anu6bRWaQMrCmLLEEMEfPt7FBBkQw==",
    "server_key": "Av2+ypalfJ7Z0bpSHc9hOUZT/mjwdIJQUtWlSc1f1Qj0tZUoCzIAZmh0Bx60hEabeOY2XJFnsSjsE7SptDLOHg==",
    "iterations": 4096
  }
}
```

The output JSON fragment can be copied directly into your users configuration file under the `scram_credentials` field.

## Trademarks

Apache Kafka is either a registered trademark or a trademark of the Apache Software Foundation in the United States and/or other countries.
