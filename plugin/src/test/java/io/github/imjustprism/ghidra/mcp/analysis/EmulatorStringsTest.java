package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class EmulatorStringsTest {

    @Test
    void findsAsciiRunAtOrAboveMinLen() {
        var b = "ab\0secret_key\0xy".getBytes(StandardCharsets.US_ASCII);
        var found = Emulator.extractStrings(b, 4);

        assertEquals(1, found.size());
        assertEquals("ascii", found.get(0).encoding());
        assertEquals("secret_key", found.get(0).text());
        assertEquals(3, found.get(0).offset());
    }

    @Test
    void shortAsciiRunsAreIgnored() {
        var b = "ab\0cd\0ef".getBytes(StandardCharsets.US_ASCII);
        assertTrue(Emulator.extractStrings(b, 4).isEmpty());
    }

    @Test
    void findsUtf16LeRun() {
        var wide = new byte[]{'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, 0, 0};
        var found = Emulator.extractStrings(wide, 4);

        var utf16 = found.stream().filter(f -> f.encoding().equals("utf16le")).toList();
        assertEquals(1, utf16.size());
        assertEquals("hello", utf16.get(0).text());
        assertEquals(0, utf16.get(0).offset());
    }

    @Test
    void reportsOffsetWithinBuffer() {
        var b = "\0\0\0\0FLAG{abc}".getBytes(StandardCharsets.US_ASCII);
        var found = Emulator.extractStrings(b, 4);

        assertEquals(1, found.size());
        assertEquals("FLAG{abc}", found.get(0).text());
        assertEquals(4, found.get(0).offset());
    }
}
