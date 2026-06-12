package io.github.imjustprism.ghidra.mcp.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PatternsTest {

    private static final byte M = (byte) 0xFF;
    private static final byte W = 0;

    @Test
    void parsesIdaSpacedTokens() {
        var s = Patterns.parse("48 8B ?? E8");
        assertArrayEquals(new byte[]{0x48, (byte) 0x8B, 0, (byte) 0xE8}, s.bytes());
        assertArrayEquals(new byte[]{M, M, W, M}, s.mask());
    }

    @Test
    void parsesContiguousSameAsSpaced() {
        assertEquals(Patterns.parse("48 8B ?? E8").ida(), Patterns.parse("488B??E8").ida());
    }

    @Test
    void parsesSingleQuestionMarkAsFullByteWildcard() {
        var s = Patterns.parse("48 ? E8");
        assertArrayEquals(new byte[]{M, W, M}, s.mask());
    }

    @Test
    void parsesCodePlusMaskForm() {
        var s = Patterns.parse("\\x48\\x8B\\x00 xx?");
        assertEquals("48 8B ??", s.ida());
        assertEquals(1, s.wildcards());
    }

    @Test
    void idaRenderIsUpperHexWithDoubleQuestionWildcards() {
        assertEquals("48 8B ?? E8", Patterns.parse("48 8b ?? e8").ida());
    }

    @Test
    void countsWildcardsAndLength() {
        var s = Patterns.parse("E8 ?? ?? ?? ??");
        assertEquals(5, s.length());
        assertEquals(4, s.wildcards());
        assertFalse(s.allWildcard());
    }

    @Test
    void allWildcardWhenEveryByteMasked() {
        assertTrue(Patterns.parse("?? ?? ??").allWildcard());
    }

    @Test
    void roundTripsThroughIdaRendering() {
        var ida = "0F 84 ?? ?? ?? ?? 48 8B";
        assertEquals(ida, Patterns.parse(ida).ida());
    }

    @Test
    void rejectsEmptyPattern() {
        assertThrows(IllegalArgumentException.class, () -> Patterns.parse("   "));
    }

    @Test
    void rejectsOddLengthContiguous() {
        assertThrows(IllegalArgumentException.class, () -> Patterns.parse("488"));
    }

    @Test
    void rejectsNonHexToken() {
        assertThrows(IllegalArgumentException.class, () -> Patterns.parse("48 ZZ"));
    }
}
