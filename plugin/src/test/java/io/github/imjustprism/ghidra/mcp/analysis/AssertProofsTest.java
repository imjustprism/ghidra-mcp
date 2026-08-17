package io.github.imjustprism.ghidra.mcp.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class AssertProofsTest {

    private static final String SIG =
            "enum Skills::SkillState::Id __cdecl Skills::GameActorShiftedSkill::OnStart"
                    + "(const class Core::Ptr<class Game::GameWorld> &)";

    private static final String SHIFTED_SKILL = """
            undefined4 FUN_1408b703c(longlong param_1,undefined8 param_2)

            {
              int *piVar1;
              int iVar15;
              longlong *plVar17;
              longlong lVar19;
              longlong *plVar22;
              int *piVar24;
              ushort uVar4;

              if (*(int *)(param_1 + 0x2c) != 0) {
                n_assert("SkillState::Ready == this->currState",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\drasa_online\\\\code\\\\shared\\\\skills\\\\gameactorshiftedskill.cc"
                         ,0x49,
                         "enum Skills::SkillState::Id __cdecl Skills::GameActorShiftedSkill::OnStart(const class Core::Ptr<class Game::GameWorld> &)"
                        );
              }
              plVar22 = (longlong *)(param_1 + 0x68);
              if (*plVar22 == 0) {
                n_assert("this->skillUser.isvalid()",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\drasa_online\\\\code\\\\shared\\\\skills\\\\gameactorshiftedskill.cc"
                         ,0x4a,
                         "enum Skills::SkillState::Id __cdecl Skills::GameActorShiftedSkill::OnStart(const class Core::Ptr<class Game::GameWorld> &)"
                        );
              }
              piVar24 = (int *)(param_1 + 0x270);
              if (*piVar24 < 1) {
                n_assert("0 < this->commands.Size()",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\drasa_online\\\\code\\\\shared\\\\skills\\\\gameactorshiftedskill.cc"
                         ,0x4b,
                         "enum Skills::SkillState::Id __cdecl Skills::GameActorShiftedSkill::OnStart(const class Core::Ptr<class Game::GameWorld> &)"
                        );
              }
              lVar19 = *(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8);
              if (*(longlong *)(lVar19 + 0x5e0) == 0) {
                n_assert("0 != Singleton",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\drasa_online\\\\code\\\\shared\\\\skills/skillmanager.h"
                         ,0x2b,"class Skills::SkillManager *__cdecl Skills::SkillManager::Instance(void)");
              }
              piVar1 = (int *)(*(longlong *)(lVar19 + 0x5e0) + 0xa8);
              if (*piVar1 <= (int)(uint)uVar4) {
                n_assert("InvalidIndex != idx && idx < this->skillInfos.Size()",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\drasa_online\\\\code\\\\shared\\\\skills/skillmanager.h"
                         ,0xbc,
                         "const class Skills::SkillInfo &__cdecl Skills::SkillManager::GetSkillInfo(int) const"
                        );
              }
              if (iVar15 + -1 < *(int *)(param_1 + 0x1bc)) {
                n_assert("this->summonMonsterAmount <= numTargetPositions - 1",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\drasa_online\\\\code\\\\shared\\\\skills\\\\gameactorshiftedskill.cc"
                         ,0x6b,
                         "enum Skills::SkillState::Id __cdecl Skills::GameActorShiftedSkill::OnStart(const class Core::Ptr<class Game::GameWorld> &)"
                        );
              }
              return 0;
            }
            """;

    private static final String FIXED_ARRAY_INDEXER = """
            longlong FUN_1401b82b8(int *param_1,int param_2)

            {
              if (((*(longlong *)(param_1 + 2) == 0) || (param_2 < 0)) || (*param_1 <= param_2)) {
                n_assert("this->elements && (index >= 0) && (index < this->size)",
                         "C:\\\\jenkins-slave\\\\workspace\\\\dro\\\\nebula3\\\\code\\\\foundation\\\\util/fixedarray.h"
                         ,0xf3,
                         "class Core::Ptr<class Skills::SkillCommand> &__cdecl Util::FixedArray<class Core::Ptr<class Skills::SkillCommand> >::operator [](int) const"
                        );
              }
              return *(longlong *)(param_1 + 2) + (longlong)param_2 * 8;
            }
            """;

    private static AssertProofs.Site site(String c, String expr) {
        for (var s : AssertProofs.sites(c)) {
            if (s.expr().equals(expr)) return s;
        }
        return null;
    }

    private static AssertProofs.Deref only(String c, AssertProofs.Frame frame, String expr) {
        var s = site(c, expr);
        assertNotNull(s, "no assert site for " + expr);
        var guard = AssertProofs.guardFor(c, s.start());
        assertNotNull(guard, "no guard for " + expr);
        var list = new java.util.ArrayList<AssertProofs.Deref>();
        for (var d : AssertProofs.derefs(guard, frame, s.start())) {
            if (d.resolved()) list.add(d);
        }
        assertEquals(1, list.size(), "expected one resolved dereference for " + expr + " got " + list);
        return list.get(0);
    }

    @Test
    void findsEverySiteWithFileAndLine() {
        var sites = AssertProofs.sites(SHIFTED_SKILL);
        assertEquals(6, sites.size());
        var s = site(SHIFTED_SKILL, "0 < this->commands.Size()");
        assertNotNull(s);
        assertEquals(0x4b, s.line());
        assertEquals("shared/skills/gameactorshiftedskill.cc", s.file());
        assertEquals(SIG, s.sig());
    }

    @Test
    void provesPlainScalarFieldOffset() {
        var frame = AssertProofs.frame(SHIFTED_SKILL);
        var d = only(SHIFTED_SKILL, frame, "SkillState::Ready == this->currState");
        assertEquals("param_1", d.base());
        assertEquals(0x2c, d.offset());
        assertEquals(4, d.width());
    }

    @Test
    void provesOffsetThroughAPointerAlias() {
        var frame = AssertProofs.frame(SHIFTED_SKILL);
        var user = only(SHIFTED_SKILL, frame, "this->skillUser.isvalid()");
        assertEquals("param_1", user.base());
        assertEquals(0x68, user.offset());
        var commands = only(SHIFTED_SKILL, frame, "0 < this->commands.Size()");
        assertEquals("param_1", commands.base());
        assertEquals(0x270, commands.offset());
    }

    @Test
    void picksTheThisOperandNotTheOtherSideOfTheCompare() {
        var frame = AssertProofs.frame(SHIFTED_SKILL);
        var d = only(SHIFTED_SKILL, frame, "this->summonMonsterAmount <= numTargetPositions - 1");
        assertEquals("param_1", d.base());
        assertEquals(0x1bc, d.offset());
    }

    @Test
    void attributesInlinedAssertsToTheirOwnClassAndBase() {
        var frame = AssertProofs.frame(SHIFTED_SKILL);
        var s = site(SHIFTED_SKILL, "InvalidIndex != idx && idx < this->skillInfos.Size()");
        assertNotNull(s);
        assertEquals("Skills::SkillManager", AssertProofs.ownerOf(s.sig()));
        var d = only(SHIFTED_SKILL, frame, s.expr());
        assertEquals("tls[0x5e0]", d.base());
        assertEquals(0xa8, d.offset());
    }

    @Test
    void derivesTheTlsSingletonSlot() {
        var frame = AssertProofs.frame(SHIFTED_SKILL);
        var d = only(SHIFTED_SKILL, frame, "0 != Singleton");
        assertEquals("tls", d.base());
        assertEquals(0x5e0, d.offset());
        var s = site(SHIFTED_SKILL, "0 != Singleton");
        assertEquals("Skills::SkillManager", AssertProofs.ownerOf(s.sig()));
    }

    @Test
    void scalesPointerArithmeticByElementSize() {
        var frame = AssertProofs.frame(FIXED_ARRAY_INDEXER);
        var s = site(FIXED_ARRAY_INDEXER, "this->elements && (index >= 0) && (index < this->size)");
        assertNotNull(s);
        var guard = AssertProofs.guardFor(FIXED_ARRAY_INDEXER, s.start());
        assertNotNull(guard);
        var offsets = new java.util.ArrayList<Long>();
        for (var d : AssertProofs.derefs(guard, frame, s.start())) {
            if (d.resolved() && "param_1".equals(d.base())) offsets.add(d.offset());
        }
        assertTrue(offsets.contains(8L), "param_1 + 2 on int* is byte 8, got " + offsets);
        assertTrue(offsets.contains(0L), "*param_1 is byte 0, got " + offsets);
    }

    @Test
    void identifiesFixedArrayFromItsAssertAndNotFromAGuess() {
        var s = site(FIXED_ARRAY_INDEXER, "this->elements && (index >= 0) && (index < this->size)");
        assertNotNull(s);
        var shape = NebulaShapes.byEvidence(s.expr(), s.file());
        assertNotNull(shape);
        assertEquals("Util::FixedArray", shape.kind());
        assertEquals(0x00, shape.sizeOff());
        assertEquals(0x08, shape.elemsOff());
        assertEquals("Core::Ptr<class Skills::SkillCommand>",
                AssertProofs.elementTypeOf(AssertProofs.ownerOf(s.sig())));
    }

    @Test
    void doesNotConfuseArrayWithFixedArray() {
        var array = NebulaShapes.byKind("Util::Array");
        var fixed = NebulaShapes.byKind("FixedArray");
        assertNotNull(array);
        assertNotNull(fixed);
        assertEquals(0x08, array.sizeOff());
        assertEquals(0x10, array.elemsOff());
        assertEquals(0x00, fixed.sizeOff());
        assertEquals(0x08, fixed.elemsOff());
        assertFalse(array.sizeOff() == fixed.sizeOff());
    }

    @Test
    void refusesAGuardThatIsNotTheAssertsOwnIf() {
        var c = """
                void FUN_x(longlong param_1)
                {
                  if (*(int *)(param_1 + 0x10) == 0) {
                    doSomething();
                  }
                  n_assert("this->foo","a/b.cc",1,"void __cdecl A::B::C(void)");
                }
                """;
        var s = site(c, "this->foo");
        assertNotNull(s);
        assertNull(AssertProofs.guardFor(c, s.start()));
    }

    @Test
    void readsFieldNamesAndOwnersOutOfTheAssertText() {
        assertEquals(List.of("currState"), AssertProofs.fieldsOf("SkillState::Ready == this->currState"));
        assertEquals(List.of("commands"), AssertProofs.fieldsOf("0 < this->commands.Size()"));
        assertEquals("Skills::GameActorShiftedSkill", AssertProofs.ownerOf(SIG));
        assertEquals("OnStart", AssertProofs.memberOf(SIG));
    }
}
