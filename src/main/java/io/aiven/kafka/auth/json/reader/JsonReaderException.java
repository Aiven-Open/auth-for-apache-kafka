/**
 * Copyright (c) 2020 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.json.reader;

public class JsonReaderException extends RuntimeException {
    public JsonReaderException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
