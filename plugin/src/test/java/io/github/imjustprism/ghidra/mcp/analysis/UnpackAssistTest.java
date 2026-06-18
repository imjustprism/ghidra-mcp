package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UnpackAssistTest {

    @Test
    void stripsLeadingDotAndLowercases() {
        assertEquals("upx0", UnpackAssist.normalizeSection(".UPX0"));
        assertEquals("vmp0", UnpackAssist.normalizeSection(".vmp0"));
        assertEquals("text", UnpackAssist.normalizeSection(".text"));
    }

    @Test
    void stripsTrailingSplitSuffix() {
        assertEquals("upx0", UnpackAssist.normalizeSection(".UPX0_1"));
        assertEquals("upx1", UnpackAssist.normalizeSection("UPX1_23"));
    }

    @Test
    void keepsNonNumericSuffixAndSpecialChars() {
        assertEquals("mpress1", UnpackAssist.normalizeSection(".MPRESS1"));
        assertEquals("fsg!", UnpackAssist.normalizeSection("FSG!"));
        assertEquals("data_x", UnpackAssist.normalizeSection(".data_x"));
    }
}
