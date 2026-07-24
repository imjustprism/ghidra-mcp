package io.github.imjustprism.ghidra.mcp.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.imjustprism.ghidra.mcp.http.Page;
import org.junit.jupiter.api.Test;

class ResponsesWindowTest {

    @Test
    void windowsByOffsetAndLimitWhileCountingTotal() {
        var w = new Responses.Window(new Page(2, 3));
        int taken = 0;
        for (int i = 0; i < 10; i++) {
            if (w.take()) taken++;
        }
        assertEquals(3, taken);
        assertEquals(10, w.total());
    }

    @Test
    void skipsExactlyOffsetRowsThenTakesLimit() {
        var w = new Responses.Window(new Page(2, 2));
        assertFalse(w.take());
        assertFalse(w.take());
        assertTrue(w.take());
        assertTrue(w.take());
        assertFalse(w.take());
        assertEquals(5, w.total());
    }
}
