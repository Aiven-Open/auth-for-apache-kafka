/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.json.reader;

import java.lang.reflect.Type;
import java.nio.file.Path;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

public abstract class AbstractJsonReader<T> implements JsonReader<T> {

    protected final Path configFile;

    protected final GsonBuilder gsonBuilder =
        new GsonBuilder()
            .registerTypeAdapter(Pattern.class, new RegexpJsonDeserializer());

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

}
