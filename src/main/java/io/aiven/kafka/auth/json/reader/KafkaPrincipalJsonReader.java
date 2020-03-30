/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.json.reader;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import io.aiven.kafka.auth.json.AivenKafkaPrincipalMapping;

import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

public class KafkaPrincipalJsonReader extends AbstractJsonReader<AivenKafkaPrincipalMapping> {

    public KafkaPrincipalJsonReader(final Path configFile) {
        super(configFile);
    }

    @Override
    public List<AivenKafkaPrincipalMapping> read() {
        try (final Reader reader = Files.newBufferedReader(configFile)) {
            final java.lang.reflect.Type t = new TypeToken<Collection<AivenKafkaPrincipalMapping>>() {}.getType();
            return gsonBuilder.create().fromJson(reader, t);
        } catch (final JsonSyntaxException | JsonIOException | IOException ex) {
            throw new JsonReaderException(
                String.format(
                    "Failed to read kafka principal mapping configuration file: %s",
                    configFile
                ), ex);
        }
    }
}
