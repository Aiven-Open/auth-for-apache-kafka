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
