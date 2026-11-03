/*
 * Copyright 2013 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.xml.security.utils;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Tests for UnsyncByteArrayOutputStream buffer growth (SANTUARIO-334).
 */
public class UnsyncByteArrayOutputStreamTest extends TestCase {

    public UnsyncByteArrayOutputStreamTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(UnsyncByteArrayOutputStreamTest.class);
    }

    public void testWriteLargerThanQuadrupleBuffer() throws Exception {
        UnsyncByteArrayOutputStream output = new UnsyncByteArrayOutputStream();
        byte[] data = new byte[100 * 1024];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        output.write(data);
        output.write(data, 0, data.length);
        output.write(7);
        byte[] result = output.toByteArray();
        assertEquals(2 * data.length + 1, result.length);
        assertEquals(data[data.length - 1], result[2 * data.length - 1]);
        assertEquals(7, result[result.length - 1]);
        output.reset();
    }

    public void testOverflowThrowsOutOfMemoryError() throws Exception {
        UnsyncByteArrayOutputStream output = new UnsyncByteArrayOutputStream();
        output.pos = Integer.MAX_VALUE;
        try {
            output.write(1);
            fail("Expected OutOfMemoryError");
        } catch (OutOfMemoryError e) {
            // expected
        }

        output.pos = Integer.MAX_VALUE - 1;
        try {
            output.write(new byte[2]);
            fail("Expected OutOfMemoryError");
        } catch (OutOfMemoryError e) {
            // expected
        }
        try {
            output.write(new byte[4], 0, 2);
            fail("Expected OutOfMemoryError");
        } catch (OutOfMemoryError e) {
            // expected
        }
        output.reset();
    }
}
