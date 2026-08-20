package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class NextGenReTest {

    @Test
    void capabilityMapsInjectionAndHttp() {
        assertEquals("process_injection", CapabilityMap.classifyImport("WriteProcessMemory"));
        assertEquals("process_injection", CapabilityMap.classifyImport("__imp_VirtualAllocEx"));
        assertEquals("c2_http", CapabilityMap.classifyImport("InternetConnectA"));
        assertEquals("", CapabilityMap.classifyImport("printf"));
    }

    @Test
    void cryptoRecipeClassifiesGcmAndHmac() {
        assertEquals("aes_gcm_decrypt",
                CryptoRecipe.classify(List.of("BCryptDecrypt"), "ChainingModeGCM"));
        assertEquals("hash", CryptoRecipe.classify(List.of("BCryptCreateHash", "BCryptHashData"), "SHA256"));
        assertTrue(CryptoRecipe.isCryptoApi("BCryptGenRandom"));
        assertFalse(CryptoRecipe.isCryptoApi("CreateFileA"));
    }

    @Test
    void secretComparesLicenseWords() {
        assertTrue(SecretCompares.isLicenseWord("No active subscription"));
        assertTrue(SecretCompares.isLicenseWord("sessionSecret"));
        assertFalse(SecretCompares.isLicenseWord("hello world"));
        assertTrue(SecretCompares.isCmpApi("strcmp"));
        assertTrue(SecretCompares.isCmpApi("__imp_memcmp"));
    }

    @Test
    void yaraEscapesAndIdent() {
        assertEquals("foo\\\"bar", IocExport.yaraEscape("foo\"bar"));
        assertEquals("GhidraMcpSample", IocExport.ident(""));
        assertEquals("R123bad", IocExport.ident("123bad"));
        assertEquals("Mortis_Engine", IocExport.ident("Mortis Engine"));
    }

    @Test
    void keystreamSeedParsesUnsigned() {
        assertEquals(0xdeadaecb09bfb3e0L, DecodeKeystream.parseU64("0xdeadaecb09bfb3e0"));
        assertEquals(0x79c692957d38084cL, DecodeKeystream.parseU64("79c692957d38084c"));
    }

    @Test
    void hashBlobLengths() {
        assertEquals("md5/aes-key", HashBlobs.classifyLen(16));
        assertEquals("sha256/aes-256", HashBlobs.classifyLen(32));
        assertEquals("sha1", HashBlobs.classifyLen(20));
        assertEquals("", HashBlobs.classifyLen(7));
        assertTrue(HashBlobs.looksRandom(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
        assertFalse(HashBlobs.looksRandom(new byte[16]));
    }

    @Test
    void peFileTime() {
        assertEquals("", PeFacts.fileTime(0));
        assertTrue(PeFacts.fileTime(1_700_000_000).startsWith("2023"));
    }

    @Test
    void selfModifyHasAny() {
        assertTrue(SelfModify.hasAny(List.of("VirtualProtect", "Sleep"), new String[]{"VirtualProtect"}));
        assertFalse(SelfModify.hasAny(List.of("Sleep"), new String[]{"VirtualProtect"}));
    }
}
