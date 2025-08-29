#pragma once
#include <xbyak/xbyak.h>
#include "Hooks/Util/HookUtil.hpp"

namespace BingusFixes {

    struct hkbStateMachine_HashLookupFail_Fix final : Xbyak::CodeGenerator {

        hkbStateMachine_HashLookupFail_Fix(uintptr_t afterSite) {

            // RAX currently = [lVar3 + 0xA0]
            test(rax, rax);
            jnz("do_load"); 

            // if null -> return, IDA says the func returns a uint32 but ghidra says its void.
            // Restore eax to the apparent default value just in case.
            mov(eax, 0x80000000);  // uint32 return in EAX
            add(rsp, 0x90);        // restore sp
            pop(rbp);              // restore pushed rbp
            ret();

            L("do_load");
            // Re-emit stolen bytes
            mov(rcx, ptr[rax + 0x10]);     // 48 8B 48 10
            lea(rax, ptr[rcx + rdx * 8]);  // 48 8D 04 D1

            // Jump back after patched site
            mov(rax, afterSite);
            jmp(rax);
        }

        static void Install() {

            // Crash site: AE RelID 59373, + 0x237 (at mov rcx,[rax+0x10])
            // rax is null due to a hashmap lookup returning null (3rd arg) as a default value.
            // statemachine::sub appears to decide what the best way to transition from one anim state to another is.
            // however if the behaviors/anims are bad this lookup fails.
            // returning early prevents the ctd but causes the anim to get stuck in the last state.
            // TODO find a way to cleanly reset the actor anim state.

            REL::Relocation<std::uintptr_t> siteRel{ REL::ID(59373), 0x237 };
            const auto site = siteRel.address();
            const auto afterSite = site + 8; // we steal MOV(4) + LEA(4)

            auto& tramp = SKSE::GetTrampoline();

            hkbStateMachine_HashLookupFail_Fix th(afterSite);
            th.ready();

            void* mem = tramp.allocate(th.getSize());
            auto   addr = reinterpret_cast<std::uintptr_t>(mem);
            std::memcpy(mem, th.getCode(), th.getSize());

            // 5-byte rel JMP -> thunk
            tramp.write_branch<5>(site, addr);

            // NOP the remaining 3 bytes of the 8-byte window
            constexpr uint8_t nops[3]{ 0x90, 0x90, 0x90 };
            REL::safe_write(site + 5, nops, sizeof(nops));

            logger::info("Installed hkbStateMachine_HashLookupFail_Fix at {:X}", site);

        }

    };

    // TODO Dont do this.

    // Same func as the null hashmap fix, crashes earlier than the above patch.
    // Reproducable by using pandora (4.0.4) and doing "sae IdleForceDefaultState" while being in midair/jumping
    // Nemesis appears to be fine and does not ctd.

    // crash is at (140ada970 48 8b 48 10 MOV param_1,qword ptr [RAX + 0x10]) -> mov rcx,[rax+10h]
	// lVar5 = *(longlong *)(*(longlong *)(lVar5 + 0xa0) + 0x10) + (longlong)param_3[1] * 0x48;
    // rax is 0x0 at this point

    struct hkbstatemachine_sub_140adcdf0_fix1 {

        static void __fastcall thunk(RE::hkbStateMachine* a_this, char* unk1, void* unk2, char unk3) {

            __try {
                func(a_this, unk1, unk2, unk3);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {}

        }

        FUNCTYPE_DETOUR func;

    };


    struct FUN_141161ac0_Fix1 {

        // lVar5 = FUN_1410e81d0(param_1 + 2, param_2 >> ((byte)*param_1 & 0x3f));
        // caller checks if var can be null. CTD happens inside the func due to a null deref.
        // If it throws just catch and ret null ourselves
        // i think the code here is scaleform related
        // TODO Patch in a check instead of this shit.
        static int64_t* __fastcall thunk(uint64_t* unk1, uint64_t unk2) {
            __try {
                return func(unk1, unk2);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
        }

        FUNCTYPE_CALL func;
    };

    inline void Install() {

        auto& Tramp = SKSE::GetTrampoline();
        Tramp.create(96);

        hkbStateMachine_HashLookupFail_Fix::Install();
        Hooks::stl::write_detour<hkbstatemachine_sub_140adcdf0_fix1>(REL::RelocationID(NULL, 59383, NULL));
        Hooks::stl::write_call<FUN_141161ac0_Fix1>(REL::RelocationID(NULL, 89682, NULL), REL::VariantOffset(NULL, 0x21, NULL));
    }


}