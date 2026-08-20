package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DecompileMinimalStdTest {

    @Test
    void dropsStringAppendThrows() {
        assertTrue(DecompileMinimal.isStdNoise("    std::__throw_length_error(\"basic_string::append\");"));
        assertTrue(DecompileMinimal.isStdNoise("std::__throw_bad_function_call();"));
        assertFalse(DecompileMinimal.isStdNoise("InternetConnectA(h, host, 443, 0, 0, 3, 0, 0);"));
    }

    @Test
    void minimizeStdRemovesNoiseKeepsHttp() {
        var src = """
                InternetConnectA(h, host, 0x1bb, 0, 0, 3, 0, 0);
                    std::__throw_length_error("basic_string::append");
                HttpOpenRequestA(c, "POST", path, 0, 0, 0, 0x80800000, 0);
                """;
        var out = DecompileMinimal.minimizeStd(src);
        assertTrue(out.contains("InternetConnectA"));
        assertTrue(out.contains("HttpOpenRequestA"));
        assertFalse(out.contains("throw_length_error"));
    }
}
