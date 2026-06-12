package io.github.imjustprism.ghidra.mcp.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class BufsTest {

    @Test
    void parsesHexIgnoringSpacesAndCase() {
        assertArrayEquals(new byte[]{0x48, (byte) 0x8B, (byte) 0xE8}, Bufs.parseHex("48 8b E8"));
    }

    @Test
    void parsesContiguousHex() {
        assertArrayEquals(new byte[]{(byte) 0xDE, (byte) 0xAD}, Bufs.parseHex("DEAD"));
    }

    @Test
    void rejectsOddLengthHex() {
        assertThrows(IllegalArgumentException.class, () -> Bufs.parseHex("ABC"));
    }

    @Test
    void encodesLowercaseHex() {
        assertEquals("488be8", Bufs.hex(new byte[]{0x48, (byte) 0x8B, (byte) 0xE8}));
    }

    @Test
    void hexAndParseHexRoundTrip() {
        assertEquals("deadbeef", Bufs.hex(Bufs.parseHex("DE AD BE EF")));
    }
}
