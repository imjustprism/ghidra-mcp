package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class NebulaNamesTest {

    @Test
    void decodesDefendFourCC() {
        long v = 0x44464e44L;
        assertTrue(NebulaNames.isFourCC(v));
        assertEquals("DFND", NebulaNames.fourCCAscii(v));
        assertEquals("0x44464e44", NebulaNames.fourCCHex(v));
    }

    @Test
    void rejectsSmallImmediatesAsFourCC() {
        assertFalse(NebulaNames.isFourCC(0));
        assertFalse(NebulaNames.isFourCC(1));
        assertFalse(NebulaNames.isFourCC(7));
        assertFalse(NebulaNames.isFourCC(0x100));
    }

    @Test
    void qualifiedClassRejectsFuncsigsAndPaths() {
        assertTrue(NebulaNames.isQualifiedClass("Messaging::Defend"));
        assertTrue(NebulaNames.isQualifiedClass("Skills::SkillManager"));
        assertFalse(NebulaNames.isQualifiedClass(
                "void __cdecl Messaging::Defend::Handle(void)"));
        assertFalse(NebulaNames.isQualifiedClass("shared/skills/skillmanager.h"));
        assertFalse(NebulaNames.isQualifiedClass("Util::Array<class Foo>"));
        assertFalse(NebulaNames.isMessagingClass("Messaging::Travel::SetDestination"));
        assertTrue(NebulaNames.isMessagingClass("Messaging::Defend"));
    }

    @Test
    void picksTheGameClassOverUtilNoise() {
        assertEquals("Messaging::Defend", NebulaNames.pickClassName(List.of(
                "0 != rtti",
                "void __cdecl Core::Factory::Register(void)",
                "Messaging::Defend",
                "Util::String")));
    }

    @Test
    void namespaceChainRespectsTemplates() {
        assertEquals(List.of("Skills", "Skills::SkillManager"),
                NebulaNames.namespaceChain("Skills::SkillManager"));
        assertEquals(List.of("Util", "Util::Array<class Core::Ptr<class Game::GameItem> >"),
                NebulaNames.namespaceChain("Util::Array<class Core::Ptr<class Game::GameItem> >"));
        assertEquals("Skills", NebulaNames.parentNamespace("Skills::SkillManager"));
        assertEquals("SkillManager", NebulaNames.leafName("Skills::SkillManager"));
    }

    @Test
    void moneyAndAttrNames() {
        assertTrue(NebulaNames.isMoneyAttr("money_rc"));
        assertTrue(NebulaNames.isMoneyAttr("money_vc_gold_no_auto_use"));
        assertFalse(NebulaNames.isMoneyAttr("Money_RC"));
        assertTrue(NebulaNames.isAttrName("goldamount"));
        assertFalse(NebulaNames.isAttrName("true"));
        assertFalse(NebulaNames.isAttrName("this"));
    }

    @Test
    void sourcePathsAndThisAsserts() {
        assertTrue(NebulaNames.looksLikeSourcePath(
                "C:\\jenkins-slave\\workspace\\dro\\nebula3\\code\\foundation\\util\\array.h"));
        assertTrue(NebulaNames.looksLikeSourcePath("shared/skills/skillmanager.h"));
        assertFalse(NebulaNames.looksLikeSourcePath("Messaging::Defend"));
        assertTrue(NebulaNames.isThisAssert("0 < this->commands.Size()"));
        assertFalse(NebulaNames.isThisAssert("0 != Singleton"));
        assertTrue(NebulaNames.isHandleMessageName("Properties_NetworkCommandCreatorProperty_HandleMessage"));
        assertTrue(NebulaNames.isFuncsig("void __cdecl Foo::Bar(void)"));
    }

    @Test
    void sourceTreeDirOf() {
        assertEquals("shared/skills", SourceTree.dirOf("shared/skills/skillmanager.h"));
        assertEquals("", SourceTree.dirOf("array.h"));
    }

    @Test
    void crtSectionNames() {
        assertTrue(Reachability.isCrtSection(".CRT$XCU"));
        assertTrue(Reachability.isCrtSection(".CRT"));
        assertTrue(Reachability.isCrtSection(".rdata$CRT$XCU"));
        assertFalse(Reachability.isCrtSection(".pdata"));
        assertFalse(Reachability.isCrtSection(".text"));
    }

    @Test
    void reachabilityVerdictPrefersCrtInitOverDead() {
        var crt = Reachability.verdict(0, 0, 0, 1, 0, 0, 0, false);
        assertTrue(crt.startsWith("crt_init"), crt);
        var atexit = Reachability.verdict(0, 0, 0, 0, 0, 0, 0, true);
        assertTrue(atexit.startsWith("crt_init"), atexit);
        var dead = Reachability.verdict(0, 0, 0, 0, 0, 0, 0, false);
        assertTrue(dead.startsWith("unreferenced"), dead);
        var vtable = Reachability.verdict(0, 2, 0, 0, 0, 0, 0, false);
        assertTrue(vtable.startsWith("only_via_vtable"), vtable);
    }

    @Test
    void namespaceMatchesIgnoresTemplateArguments() {
        assertTrue(NebulaNames.namespaceMatches("Skills::GameSkill", "Skills"));
        assertTrue(NebulaNames.namespaceMatches("Skills::GameSkill", "skills::"));
        assertTrue(NebulaNames.namespaceMatches("Messaging::UseItem", "Messaging"));
        assertFalse(NebulaNames.namespaceMatches("Core::Ptr<class Skills::GameSkill>", "Skills"));
        assertFalse(NebulaNames.namespaceMatches("Util::Array<class Game::GameItem>", "Game"));
        assertTrue(NebulaNames.namespaceMatches("Game::ClientGameWorld", "Game"));
    }

    @Test
    void pickFourCCTakesTheFirstPrintable() {
        assertEquals("0x44464e44", NebulaNames.pickFourCC(List.of(1L, 7L, 0x44464e44L, 0x20L)));
        assertEquals("", NebulaNames.pickFourCC(List.of(0L, 1L, 7L)));
    }
}
