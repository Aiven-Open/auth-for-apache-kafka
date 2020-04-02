/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.json;

import com.google.gson.annotations.SerializedName;

public final class UsernamePassword {

    @SerializedName("username")
    private final String name;

    @SerializedName("password")
    private final String password;

    public UsernamePassword(final String name, final String password) {
        this.name = name;
        this.password = password;
    }

    public String name() {
        return name;
    }

    public String password() {
        return password;
    }

}
