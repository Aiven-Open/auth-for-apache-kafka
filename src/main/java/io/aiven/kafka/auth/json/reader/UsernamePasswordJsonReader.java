/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.json.reader;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import io.aiven.kafka.auth.json.UsernamePassword;

import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

public class UsernamePasswordJsonReader extends AbstractJsonReader<UsernamePassword> {
    public UsernamePasswordJsonReader(final Path configFile) {
        super(configFile);
    }

    @Override
    public List<UsernamePassword> read() throws JsonReaderException {
        try (final Reader reader = Files.newBufferedReader(configFile)) {
            final Type t = new TypeToken<Collection<UsernamePassword>>() {}.getType();
            return gsonBuilder.create().fromJson(reader, t);
        } catch (final JsonSyntaxException | JsonIOException | IOException ex) {
            throw new JsonReaderException(
                String.format(
                    "Failed to read user/password configuration file: %s", configFile
                ), ex);
        }
    }
}
