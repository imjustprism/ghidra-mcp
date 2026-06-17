package io.github.imjustprism.ghidra.mcp.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PointerPathTest {

    @Test
    void parsesHexOffsetsWithOptionalPrefixAndSign() {
        assertArrayEquals(new long[]{0x18, 0x40, -0x8}, PointerPath.parseOffsets("0x18, 40, -8"));
    }

    @Test
    void emptyOffsetsYieldEmptyArray() {
        assertArrayEquals(new long[0], PointerPath.parseOffsets(""));
        assertArrayEquals(new long[0], PointerPath.parseOffsets(null));
    }

    @Test
    void rejectsEmptyOffsetComponent() {
        assertThrows(IllegalArgumentException.class, () -> PointerPath.parseOffsets("0x10,,0x20"));
    }

    @Test
    void decodesLittleEndianPointer() {
        var b = new byte[]{0x10, 0x20, 0x40, (byte) 0x80, 0, 0, 0, 0};
        assertEquals(0x80402010L, PointerPath.toUnsignedLong(b, 8, false));
    }

    @Test
    void decodesBigEndianPointer() {
        var b = new byte[]{0, 0, 0x20, 0x10};
        assertEquals(0x2010L, PointerPath.toUnsignedLong(b, 4, true));
    }

    @Test
    void rejectsShortBuffer() {
        assertThrows(IllegalArgumentException.class,
                () -> PointerPath.toUnsignedLong(new byte[]{1, 2}, 8, false));
    }
}
