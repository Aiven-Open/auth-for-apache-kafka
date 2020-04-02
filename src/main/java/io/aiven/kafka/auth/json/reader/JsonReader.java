/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.json.reader;

import java.util.List;

public interface JsonReader<T> {

    List<T> read() throws JsonReaderException;

}
