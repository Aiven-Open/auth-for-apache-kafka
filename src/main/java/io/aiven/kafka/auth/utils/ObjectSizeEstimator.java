/*
 * Copyright 2025 Aiven Oy https://aiven.io
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

package io.aiven.kafka.auth.utils;

public class ObjectSizeEstimator {

    private ObjectSizeEstimator() {
        // Prevent instantiation
    }

    /**
     * Estimates the size of a String object in Java.
     * This is a rough estimate. The real size may vary based on JVM implementation and settings.
     *
     * @param s the String to estimate the size of
     * @return estimated size in bytes
     */
    public static int estimateStringSize(final String s) {
        /*
        Example: "Hello, World!" (13 chars)
        
        String object:
        - Header:            12 bytes
        - Coder:             1 byte
        - Hash:              4 bytes
        - value reference:   4 bytes  (Compressed OOPs)
        - Padding:           3 bytes  (for alignment)
        ------------------------------------------------
                             24 bytes

        byte[] array:
        - Header:            12 bytes
        - Length field:      4 bytes
        - Data:              13 bytes (1 byte per char, since Java 9 for Latin-1)
        - Padding:           3 bytes (for 8-byte alignment)
        ------------------------------------------------
                             32 bytes
        
        Total:               56 bytes
        */
        if (s == null) {
            return 0;
        }
        final int stringObjectSize = 24; // Object header + coder + hash + ref + alignment
        int charArraySize = s.length() + 16; // 1 byte per char + header + length
        charArraySize += (charArraySize % 8 == 0) ? 0 : (8 - (charArraySize % 8)); // Padding for alignment
        return stringObjectSize + charArraySize; 
    }

    /**
     * Estimates the size of a Boolean object in Java.
     * This is a rough estimate. The real size may vary based on JVM implementation and settings.
     *
     * @param b the Boolean to estimate the size of
     * @return estimated size in bytes
     */
    public static int estimateBooleanSize(final Boolean b) {
        if (b == null) {
            return 0;
        }
        return 12 + 4; // Object header + ref
    }

    /**
     * Estimates the overhead of a cache entry in Java.
     * This is a rough estimate. The real size may vary based on JVM implementation and settings.
     *
     * @return estimated size in bytes
     */
    public static int estimateEntryOverhead() {
        return 12 + 4 + 4 + 4; // Object header + key ref + value ref + hash
    }
    
}
