package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import org.junit.jupiter.api.Test;

class AuthSurfaceClassifyTest {

    @Test
    void classifiesApiPathHostAndJson() {
        var rows = new ArrayList<String[]>();
        AuthSurface.classifyText("POST /api/auth/login to mortisengine.com", rows);
        AuthSurface.classifyText("{\"username\":\"x\",\"hwid\":\"ab\"}", rows);
        AuthSurface.classifyText("Authorization: Bearer abc", rows);
        AuthSurface.classifyText("|drm-v1", rows);
        var kinds = rows.stream().map(r -> r[0]).toList();
        assertTrue(kinds.contains("endpoint_path"));
        assertTrue(kinds.contains("host"));
        assertTrue(kinds.contains("json_key"));
        assertTrue(kinds.contains("http_header"));
        assertTrue(kinds.contains("crypto_marker"));
    }
}
