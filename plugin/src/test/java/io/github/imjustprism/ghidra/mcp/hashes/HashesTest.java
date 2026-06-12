package io.github.imjustprism.ghidra.mcp.hashes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class HashesTest {

    @Test
    void fnv1aEmptyIsOffsetBasis() {
        assertEquals(0x811c9dc5, Hashes.fnv1a("", true));
    }

    @Test
    void djb2EmptyIsSeed() {
        assertEquals(5381, Hashes.djb2(""));
    }

    @Test
    void crc32EmptyIsZero() {
        assertEquals(0, Hashes.crc32(""));
    }

    @Test
    void fnv1aUpperFoldsCase() {
        assertEquals(Hashes.fnv1a("KERNEL32", true), Hashes.fnv1a("kernel32", true));
    }

    @Test
    void fnv1aLowerKeepsCaseDistinct() {
        assertNotEquals(Hashes.fnv1a("KERNEL32", false), Hashes.fnv1a("kernel32", false));
    }

    @Test
    void algorithmsAreDeterministic() {
        assertEquals(Hashes.fnv1a("LoadLibraryA", true), Hashes.fnv1a("LoadLibraryA", true));
        assertEquals(Hashes.djb2("LoadLibraryA"), Hashes.djb2("LoadLibraryA"));
        assertEquals(Hashes.crc32("LoadLibraryA"), Hashes.crc32("LoadLibraryA"));
    }
}
