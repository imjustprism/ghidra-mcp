package io.github.imjustprism.ghidra.mcp.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;

class PageTest {

    @Test
    void parsesOffsetAndLimit() {
        var p = Page.from(Map.of("offset", "5", "limit", "10"));
        assertEquals(5, p.offset());
        assertEquals(10, p.limit());
    }

    @Test
    void defaultsLimitWhenAbsent() {
        var p = Page.from(Map.of());
        assertEquals(0, p.offset());
        assertEquals(Page.DEFAULT_LIMIT, p.limit());
    }

    @Test
    void clampsLimitToMax() {
        var p = Page.from(Map.of("limit", "99999"));
        assertEquals(Page.MAX_LIMIT, p.limit());
    }

    @Test
    void defaultsLimitWhenNonPositive() {
        var p = Page.from(Map.of("limit", "0"));
        assertEquals(Page.DEFAULT_LIMIT, p.limit());
    }
}
