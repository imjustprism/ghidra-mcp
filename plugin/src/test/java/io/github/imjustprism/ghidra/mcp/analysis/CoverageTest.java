package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class CoverageTest {

    @Test
    void takesBareAddress() {
        assertEquals("0x401000", Coverage.addressToken("0x401000"));
        assertEquals("00401000", Coverage.addressToken("  00401000  "));
    }

    @Test
    void stripsSpaceAndTabSeparatedHitCounts() {
        assertEquals("0x401000", Coverage.addressToken("0x401000 5"));
        assertEquals("0x401000", Coverage.addressToken("0x401000\t5"));
    }

    @Test
    void stripsInlineComments() {
        assertEquals("0x401000", Coverage.addressToken("0x401000;this is a comment"));
        assertEquals("0x401000", Coverage.addressToken("0x401000#count=5"));
    }

    @Test
    void returnsEmptyForCommentsAndBlanks() {
        assertEquals("", Coverage.addressToken("# full line comment"));
        assertEquals("", Coverage.addressToken("; drcov header"));
        assertEquals("", Coverage.addressToken("   "));
    }
}
