package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class FieldWritesTest {

    @Test
    void extractsParamOffsetWrites() {
        var rows = FieldWrites.extract("""
                *(undefined4 *)(param_1 + 0x50) = &A::RcMob::vftable;
                *(float *)(param_1 + 244) = fVar1;
                if (*(int *)(param_1 + 4) == 0) {
                }
                """);

        assertEquals(2, rows.size());
        assertEquals("vtable", rows.get(0).kind());
        assertEquals("0x50", rows.get(0).offset());
        assertEquals("field", rows.get(1).kind());
        assertEquals("0xf4", rows.get(1).offset());
    }

    @Test
    void extractsThisFieldWrites() {
        var rows = FieldWrites.extract("""
                this->field_368 = rider_id;
                this->state += 1;
                """);

        assertEquals(1, rows.size());
        assertEquals("0x368", rows.get(0).offset());
        assertEquals("rider_id", rows.get(0).rhs());
    }
}
