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

package io.aiven.kafka.auth.json.reader;

import java.lang.reflect.Type;
import java.nio.file.Path;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import io.aiven.kafka.auth.json.AclOperationType;
import io.aiven.kafka.auth.json.AclPermissionType;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;


public abstract class AbstractJsonReader<T> implements JsonReader<T> {

    protected final Path configFile;

    protected final GsonBuilder gsonBuilder =
        new GsonBuilder()
            .registerTypeAdapter(Pattern.class, new RegexpJsonDeserializer())
            .registerTypeAdapter(AclOperationType.class, new AclOperationTypeDeserializer())
            .registerTypeAdapter(AclPermissionType.class, new AclPermissionTypeDeserializer());

    protected AbstractJsonReader(final Path configFile) {
        this.configFile = configFile;
    }

    protected static class RegexpJsonDeserializer implements JsonDeserializer<Pattern> {
        @Override
        public Pattern deserialize(final JsonElement jsonElement,
                                   final Type type,
                                   final JsonDeserializationContext ctx) throws JsonParseException {
            try {
                return !jsonElement.isJsonNull() ? Pattern.compile(jsonElement.getAsString()) : null;
            } catch (final PatternSyntaxException e) {
                throw new JsonParseException("Couldn't compile pattern", e);
            }
        }
    }

    protected static class AclPermissionTypeDeserializer implements JsonDeserializer<AclPermissionType> {
        @Override
        public AclPermissionType deserialize(final JsonElement jsonElement,
                                             final Type type,
                                             final JsonDeserializationContext ctx) throws JsonParseException {
            try {
                if (jsonElement.isJsonNull()) {
                    return AclPermissionType.ALLOW;
                }
                return AclPermissionType.valueOf(jsonElement.getAsString().toUpperCase());
            } catch (final IllegalArgumentException e) {
                throw new JsonParseException("Cannot deserialize permission type", e);
            }
        }
    }

    protected static class AclOperationTypeDeserializer implements JsonDeserializer<AclOperationType> {
        @Override
        public AclOperationType deserialize(final JsonElement jsonElement,
                                             final Type type,
                                             final JsonDeserializationContext ctx) throws JsonParseException {
            try {
                if (jsonElement.isJsonNull()) {
                    return AclOperationType.Unknown;
                }
                return AclOperationType.valueOf(jsonElement.getAsString());
            } catch (final IllegalArgumentException e) {
                throw new JsonParseException("Cannot deserialize operation type", e);
            }
        }
    }
}
