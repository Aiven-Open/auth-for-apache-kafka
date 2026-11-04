/*
 * Copyright 2026 Aiven Oy https://aiven.io
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

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Generates ACL files for {@link AclScaleBenchmark}.
 *
 * <p>A file starts with a few system rules, then has the user rules of the chosen {@link Profile}, and ends with
 * catch-all rules. User {@code i} owns input ACLs {@code i * aclsPerUser} to {@code (i + 1) * aclsPerUser - 1}.
 *
 * <p>The topic and group prefixes returned here are granted by a glob or prefix rule, so any name starting with them
 * is allowed. Benchmarks append a counter to get a resource the authorizer has not seen yet.
 */
public final class AclFileGenerator {

    /** Kind of user rules. Public because JMH-generated code sets it as a benchmark parameter. */
    public enum Profile {
        /** Each user's topics and topic globs combined into one regex rule per operation. */
        REGEX,
        /** One rule per ACL on a literal or prefixed topic or group; every {@code denyEvery}-th is a DENY. */
        NATIVE
    }

    static final String UNKNOWN_USER = "user-unknown";

    private static final String ALL = "^(.*)$";
    private static final String[] PERMISSIONS = {"readwrite", "read", "write"};
    private static final String[] NATIVE_OPERATIONS = {"Write", "Read", "Describe"};

    private final Profile profile;
    private final int aclsPerUser;
    private final int denyEvery;
    private final int userCount;
    private final int firstUserAcl;
    private final int lastUserAcl;

    AclFileGenerator(final Profile profile, final int aclCount, final int aclsPerUser, final int denyEvery) {
        if (aclsPerUser < 1 || aclCount < aclsPerUser || aclCount % aclsPerUser != 0) {
            throw new IllegalArgumentException("aclCount must be a positive multiple of aclsPerUser");
        }
        this.profile = profile;
        this.aclsPerUser = aclsPerUser;
        this.denyEvery = denyEvery;
        this.userCount = aclCount / aclsPerUser;
        this.firstUserAcl = writableByPrefix(0, true);
        this.lastUserAcl = writableByPrefix(userCount - 1, false);
    }

    String firstUser() {
        return user(0);
    }

    String lastUser() {
        return user(userCount - 1);
    }

    /** Topic prefix the first user may write to, through its first writable glob or prefix rule. */
    String firstUserTopicPrefix() {
        return topic(0, firstUserAcl) + "-";
    }

    /** Topic prefix the last user may write to, through its last writable glob or prefix rule. */
    String lastUserTopicPrefix() {
        return topic(userCount - 1, lastUserAcl) + "-";
    }

    /** Group prefix the last user may read. */
    String lastUserGroupPrefix() {
        return group(userCount - 1);
    }

    /** Writes the file and returns its number of entries. */
    int write(final Path path) throws IOException {
        final JsonArray acls = new JsonArray();
        systemRules(acls);
        if (profile == Profile.REGEX) {
            regexRules(acls);
        } else {
            nativeRules(acls);
        }
        acls.add(rule(ALL, List.of("DescribeConfigs"), "^Cluster:(.*)$", "ALLOW"));
        try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            new GsonBuilder().disableHtmlEscaping().create().toJson(acls, writer);
        }
        return acls.size();
    }

    /** DENY rules on system topics, rules for another principal type, and service accounts with full access. */
    private static void systemRules(final JsonArray acls) {
        for (final String topic : List.of("system-a", "system-b", "system-c")) {
            acls.add(rule(ALL, List.of("All"), "^Topic:(" + topic + ")$", "DENY"));
        }
        acls.add(typed(rule(ALL, List.of("Describe"), ALL, "ALLOW")));
        final JsonObject templated = typed(rule("^node-(?<group>[a-z0-9]+)$", List.of("Read", "Write"), null, "ALLOW"));
        templated.addProperty("resource_pattern", "^Topic:${group}-(.*)");
        acls.add(templated);
        for (int i = 1; i <= 6; i++) {
            acls.add(rule(principal("service-" + i), List.of("All"), ALL, "ALLOW"));
        }
    }

    /** Per user, one Read and one Write rule over its topics, then catch-all rules listing all users. */
    private void regexRules(final JsonArray acls) {
        final List<String> users = new ArrayList<>();
        for (int u = 0; u < userCount; u++) {
            final List<String> readable = new ArrayList<>();
            final List<String> writable = new ArrayList<>();
            for (int acl = 0; acl < aclsPerUser; acl++) {
                final String permission = PERMISSIONS[acl % PERMISSIONS.length];
                final String topic = topic(u, acl) + (acl % 2 == 1 ? "(.*)" : "");
                if (permission.contains("read")) {
                    readable.add(topic);
                }
                if (permission.contains("write")) {
                    writable.add(topic);
                }
            }
            users.add(user(u));
            acls.add(rule(principal(user(u)), List.of("Read"), topics(readable), "ALLOW"));
            if (!writable.isEmpty()) {
                acls.add(rule(principal(user(u)), List.of("Write"), topics(writable), "ALLOW"));
            }
        }
        final String everyone = "^(" + String.join("|", users) + ")$";
        acls.add(rule(everyone, List.of("Describe", "DescribeConfigs"), "^Topic:(.*)$", "ALLOW"));
        acls.add(rule(everyone, List.of("Describe", "Read"), "^Group:(.*)$", "ALLOW"));
        acls.add(rule(everyone, List.of("Describe"), "^Cluster:(.*)$", "ALLOW"));
        acls.add(rule(everyone, List.of("Describe", "Write"), "^TransactionalId:(.*)$", "ALLOW"));
        acls.add(rule(everyone, List.of("IdempotentWrite"), "^Cluster:(.*)$", "ALLOW"));
    }

    /** ACL 0 of each user grants Read on its groups; the others cycle through operations and resource types. */
    private void nativeRules(final JsonArray acls) {
        for (int u = 0; u < userCount; u++) {
            for (int acl = 0; acl < aclsPerUser; acl++) {
                final boolean deny = isDeny(u, acl);
                final JsonObject entry = rule(principal(user(u)), List.of(nativeOperation(acl)), null,
                    deny ? "DENY" : "ALLOW");
                entry.addProperty("host", "*");
                if (acl == 0) {
                    entry.addProperty("resource_prefix", "Group:" + group(u));
                } else if (deny) {
                    entry.addProperty("resource_literal", "Topic:restricted-" + topic(u, acl));
                } else {
                    entry.addProperty(acl % 2 == 1 ? "resource_prefix" : "resource_literal", "Topic:" + topic(u, acl));
                }
                acls.add(entry);
            }
        }
    }

    /** The first or last ACL of {@code user} that allows writing any topic starting with its name. */
    private int writableByPrefix(final int user, final boolean first) {
        for (int i = 0; i < aclsPerUser; i++) {
            final int acl = first ? i : aclsPerUser - 1 - i;
            final boolean writable = profile == Profile.REGEX
                ? PERMISSIONS[acl % PERMISSIONS.length].contains("write")
                : nativeOperation(acl).equals("Write") && !isDeny(user, acl);
            if (acl % 2 == 1 && writable) {
                return acl;
            }
        }
        throw new IllegalArgumentException(profile + " with aclsPerUser=" + aclsPerUser + " and denyEvery="
            + denyEvery + " leaves user " + user + " without a writable glob or prefix rule");
    }

    private static String nativeOperation(final int acl) {
        return acl == 0 ? "Read" : NATIVE_OPERATIONS[(acl - 1) % NATIVE_OPERATIONS.length];
    }

    /** The group ACL is never a DENY, so every user can consume. */
    private boolean isDeny(final int user, final int acl) {
        return acl > 0 && denyEvery > 0 && (user * aclsPerUser + acl) % denyEvery == denyEvery - 1;
    }

    private static JsonObject rule(final String principal, final List<String> operations, final String resource,
                                   final String permission) {
        final JsonObject entry = new JsonObject();
        entry.addProperty("principal_type", "User");
        entry.addProperty("principal", principal);
        final JsonArray ops = new JsonArray();
        operations.forEach(ops::add);
        entry.add("operations", ops);
        if (resource != null) {
            entry.addProperty("resource", resource);
        }
        entry.addProperty("permission_type", permission);
        return entry;
    }

    /** Assigns a principal type that user requests never match. */
    private static JsonObject typed(final JsonObject entry) {
        entry.addProperty("principal_type", "Node");
        return entry;
    }

    private static String principal(final String name) {
        return "^(" + name + ")$";
    }

    private static String topics(final List<String> topics) {
        return "^Topic:(" + String.join("|", topics) + ")$";
    }

    private static String user(final int user) {
        return String.format("user-%06d", user);
    }

    private static String topic(final int user, final int acl) {
        return String.format("app-%06d-%03d", user, acl);
    }

    private static String group(final int user) {
        return "group-" + user(user) + "-";
    }
}
