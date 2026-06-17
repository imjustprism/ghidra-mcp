package io.github.imjustprism.ghidra.mcp.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class NamingConventionTest {

    @Test
    void snakeLowercasesAndSeparatesWords() {
        assertEquals("decode_buffer", NamingConvention.SNAKE.apply("DecodeBuffer"));
        assertEquals("decode_buffer", NamingConvention.SNAKE.apply("decodeBuffer"));
        assertEquals("decode_buffer", NamingConvention.SNAKE.apply("decode_buffer"));
    }

    @Test
    void pascalAndCamelRebuildFromSnake() {
        assertEquals("DecodeBuffer", NamingConvention.PASCAL.apply("decode_buffer"));
        assertEquals("decodeBuffer", NamingConvention.CAMEL.apply("decode_buffer"));
    }

    @Test
    void screamingSnakeUppercases() {
        assertEquals("DECODE_BUFFER", NamingConvention.SCREAMING_SNAKE.apply("decodeBuffer"));
    }

    @Test
    void splitsAcronymRunsBeforeWord() {
        assertEquals("http_server_init", NamingConvention.SNAKE.apply("HTTPServerInit"));
        assertEquals("parse_url", NamingConvention.SNAKE.apply("parseURL"));
    }

    @Test
    void keepsDigitsAttachedToPrecedingWord() {
        assertEquals("sha256_init", NamingConvention.SNAKE.apply("Sha256Init"));
    }

    @Test
    void splitsLowercaseWordAfterDigits() {
        assertEquals("foo2_bar", NamingConvention.SNAKE.apply("foo2bar"));
        assertEquals("crc32_table", NamingConvention.SNAKE.apply("crc32table"));
        assertEquals("aes256_decrypt", NamingConvention.SNAKE.apply("aes256decrypt"));
    }

    @Test
    void emptyOrSymbolOnlyReturnsInput() {
        assertEquals("", NamingConvention.SNAKE.apply(""));
        assertEquals("___", NamingConvention.SNAKE.apply("___"));
    }

    @Test
    void fromParsesAliasesAndRejectsUnknown() {
        assertEquals(NamingConvention.SCREAMING_SNAKE, NamingConvention.from("upper_snake"));
        assertEquals(NamingConvention.PASCAL, NamingConvention.from("PascalCase"));
        assertNull(NamingConvention.from("kebab"));
        assertNull(NamingConvention.from(null));
    }
}
