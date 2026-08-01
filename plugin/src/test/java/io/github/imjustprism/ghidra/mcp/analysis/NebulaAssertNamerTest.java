package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NebulaAssertNamerTest {

    private static final String CONSOLE_WARNING_DECOMP = """
            void FUN_140ca1900(longlong param_1,undefined8 param_2,undefined8 param_3) {
               EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 24));
               if (*(char *)(param_1 + 96) == '\\0') {
                  n_assert("this->IsOpen()",
                           "C:\\\\jenkins\\\\nebula3\\\\code\\\\foundation\\\\io\\\\console.cc",
                           323,"void __cdecl IO::Console::Warning(const char *,char *)");
               }
               LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 24));
               return;
            }
            """;

    @Test
    void extractsConsoleWarningFromNAssert() {
        var hit = NebulaAssertNamer.extractName(CONSOLE_WARNING_DECOMP);
        assertNotNull(hit);
        assertEquals("n_assert", hit.source());
        assertEquals("IO_Console_Warning", hit.ghidraName());
        assertTrue(hit.file() != null && hit.file().contains("console.cc"));
        assertEquals("323", hit.line());
    }

    @Test
    void extractsFromUnnamedFunAssertHelper() {
        var c = """
                void FUN_x(void) {
                  FUN_140cc6178("this->IsOpen()",
                    "C:\\\\path\\\\console.cc", 323,
                    "void __cdecl IO::Console::Open(void)");
                }
                """;
        var hit = NebulaAssertNamer.extractName(c);
        assertNotNull(hit);
        assertEquals("IO_Console_Open", hit.ghidraName());
    }

    @Test
    void fromSignatureStringParsesCdecl() {
        var hit = NebulaAssertNamer.fromSignatureString(
                "void __cdecl Util::Array<class Util::String>::Destroy(class Util::String *)");
        assertNotNull(hit);
        assertEquals("sig_string", hit.source());
        assertTrue(hit.ghidraName().startsWith("Util_Array6"));
    }

    @Test
    void isCdeclSignatureDetects() {
        assertTrue(NebulaAssertNamer.isCdeclSignature(
                "void __cdecl Game::EntityManager::Instance(void)"));
        assertTrue(!NebulaAssertNamer.isCdeclSignature("hello world"));
    }

    @Test
    void sanitizesTemplateQualifiedNames() {
        assertEquals("Core_Ptr6IO_ConsoleHandler9",
                NebulaAssertNamer.sanitize("Core::Ptr<IO::ConsoleHandler>"));
        assertEquals("Util_Array6int1float9",
                NebulaAssertNamer.sanitize("Util::Array<int,float>"));
    }

    @Test
    void stripsClassKeywordAndSpaces() {
        assertEquals("Network_NetStream",
                NebulaAssertNamer.sanitize("class Network::NetStream"));
    }

    @Test
    void rejectsInconsistentAssertNames() {
        var c = """
                void FUN_x(void) {
                  n_assert("a","f.cc",1,"void Foo::A(void)");
                  n_assert("b","f.cc",2,"void Bar::B(void)");
                }
                """;
        assertNull(NebulaAssertNamer.extractName(c));
    }

    @Test
    void skipsInstanceSingletons() {
        var c = """
                void FUN_x(void) {
                  n_assert("x","f.cc",1,"Game::ClientGameWorld * __cdecl Game::ClientGameWorld::Instance(void)");
                }
                """;
        assertNull(NebulaAssertNamer.extractName(c));
    }

    @Test
    void extractsFromNError() {
        var c = """
                void FUN_x(void) {
                  n_error("IO::Console::Error(const char *) failed");
                }
                """;
        var hit = NebulaAssertNamer.extractName(c);
        assertNotNull(hit);
        assertEquals("n_error", hit.source());
        assertEquals("IO_Console_Error", hit.ghidraName());
    }

    @Test
    void replaceInBracketsOnlyTouchesTemplates() {
        assertEquals("A::B<C_D>",
                NebulaAssertNamer.replaceInBrackets("A::B<C::D>", "::", "_"));
    }

    @Test
    void qualifiedFromSignatureHandlesCdecl() {
        assertEquals("IO::Console::Warning",
                NebulaAssertNamer.qualifiedFromSignature(
                        "void __cdecl IO::Console::Warning(const char *,char *)"));
    }

    @Test
    void qualifiedFromSignatureKeepsTemplateAndOperator() {
        assertEquals("Util::Array<Util::String>::operator =",
                NebulaAssertNamer.qualifiedFromSignature(
                        "void __cdecl Util::Array<class Util::String>::operator =(const class Util::Array<class Util::String> &)"));
    }

    @Test
    void sanitizeOperatorEquals() {
        assertEquals("Util_Array6Util_String9_operator",
                NebulaAssertNamer.sanitize("Util::Array<Util::String>::operator ="));
    }

    @Test
    void pickInstanceFunctionEmptyIsNull() {
        assertNull(NebulaSingletons.pickInstanceFunction(java.util.List.of()));
        assertNull(NebulaSingletons.pickInstanceFunction(null));
    }
}
