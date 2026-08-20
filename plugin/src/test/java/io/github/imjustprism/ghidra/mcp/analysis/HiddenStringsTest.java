package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HiddenStringsTest {

    /** MortisEngine Login User-Agent blob + seed from the 2026 sample. */
    @Test
    void splitMixDecodesMortisUserAgent() {
        var blob = hex("a0a8fd2bb4e843289ba1db290275b4e7");
        var out = HiddenStrings.decodeSplitMix(blob, 0xdeadaecb09bfb3e0L);
        assertEquals("MortisEngine/1.0", HiddenStrings.longestPrintable(out, 4));
    }

    @Test
    void splitMixDecodesMortisHost() {
        var blob = hex("3dc6e5642da87af670ceca1469603577");
        var out = HiddenStrings.decodeSplitMix(blob, 0x79c692957d38084cL);
        assertEquals("mortisengine.com", HiddenStrings.longestPrintable(out, 4));
    }

    @Test
    void splitMixDecodesApiLoginPath() {
        var blob = hex("cfa9a37c9224bf35d41cd3dddacb4b");
        var out = HiddenStrings.decodeSplitMix(blob, 0x28ec1adce6095f88L);
        assertEquals("/api/auth/login", HiddenStrings.longestPrintable(out, 4));
    }

    @Test
    void rollingXorWithIncrement() {
        var plain = "https://c2.example".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        var blob = new byte[plain.length];
        int k = 0x41;
        for (int i = 0; i < plain.length; i++) {
            blob[i] = (byte) (plain[i] ^ k);
            k = (k + 1) & 0xFF;
        }
        var out = HiddenStrings.decodeRollingXor(blob, 0x41, 1);
        assertEquals("https://c2.example", HiddenStrings.longestPrintable(out, 4));
    }

    @Test
    void longestPrintableStopsAtNul() {
        var b = "abc\0def".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        assertEquals("abc", HiddenStrings.longestPrintable(b, 3));
    }

    @Test
    void splitMixConstantsRecognized() {
        assertTrue(HiddenStrings.isSplitMixConst(HiddenStrings.GOLDEN));
        assertTrue(HiddenStrings.isSplitMixConst(HiddenStrings.MULT1));
        assertTrue(HiddenStrings.isSplitMixConst(HiddenStrings.MULT2));
        assertFalse(HiddenStrings.isSplitMixConst(0x1234));
    }

    @Test
    void printableRatioOfAscii() {
        var b = "hello".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        assertEquals(1.0, HiddenStrings.printableRatio(b, b.length), 0.01);
    }

    private static byte[] hex(String s) {
        int n = s.length() / 2;
        var out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
