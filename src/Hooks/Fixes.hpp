#pragma once
#include <xbyak/xbyak.h>
#include "Hooks/Util/HookUtil.hpp"

namespace BingusFixes {

    // Crash site: AE RelID 59373, + 0x237 (at mov rcx,[rax+0x10]) and
    // AE RelID 59373, + 0x2d0 (at mov rcx,[rax+0x10])

	// rax is null due to a hashmap lookup returning null (3rd arg) as a default value i believe.
	// hkbStateMachine::sub appears to decide what the best way to transition from one anim state to another is.
	// however if the behaviors/anims are bad this lookup fails.
	// returning early prevents the ctd but causes the anim to get stuck in the last state.

    //Edit: I reset pandora and now behaviors appear to be correct? The null hashmap doesn't trigger anymore

	// TODO find a way to cleanly reset the actor anim state.

    struct hkbStateMachine_NullGuard final : Xbyak::CodeGenerator {

        static inline constexpr size_t bytesToPatch = 8;  // LEA+MOV

    	/*if (!rax) {
		    return INT32_MIN;
		}*/

        hkbStateMachine_NullGuard() {

            test(rax, rax);
            jnz("do_load");

            // restore stack & registers
            add(rsp, 0x90);
            pop(rbp);

            mov(eax, 0x80000000);  // return INT32_MIN
            ret();

            L("do_load");
            // Re-emit stolen bytes
            mov(rcx, ptr[rax + 0x10]);     // 48 8B 48 10
            lea(rax, ptr[rcx + rdx * 8]);  // 48 8D 04 D1

            // Load jump target from literal (will be patched per-site)
            mov(r11, ASM_JMPTARGET_PH);
            jmp(r11);
        }

    };

    // Some random scaleform subroutine
    // Most callers appear to check if this func returns null
    // CTD gets triggered sometimes by SL P+ UI

    struct ScaleformSub_NullGuard final : Xbyak::CodeGenerator {

        static inline constexpr size_t bytesToPatch = 11;  // LEA+MOV+CMP

        /*if (!rdx) {
            return nullptr;
         }*/

        ScaleformSub_NullGuard(){
            
            test(rdx, rdx);
            jnz("do_load");

            //Restore registers & stack
            mov(rsi, ptr[rsp + 0x38]);
            mov(rbx, ptr[rsp + 0x30]);
            add(rsp, 0x20);
            pop(rdi);

            mov(rax, 0);  // return nullptr
            ret();

            L("do_load");
            // Original stolen instructions
            lea(rax, ptr[rdi + r8 * 8]);
            mov(rcx, ptr[rdx + 0x8]);      // 48 8B 4A 08
            cmp(rdx, rcx);                 // 48 3B D1

            // Load jump target from literal (will be patched per-site)
            mov(r11, ASM_JMPTARGET_PH);
            jmp(r11);
        }

    };

    inline void Install() {

        auto& Trampoline = SKSE::GetTrampoline();
        Trampoline.create(192);

        Hooks::stl::write_xbyak_thunk<ScaleformSub_NullGuard>(Relocation{ REL::ID(87792), 0x10f });
        Hooks::stl::write_xbyak_thunk<hkbStateMachine_NullGuard>(Relocation{ REL::ID(59373), 0x237 });
        Hooks::stl::write_xbyak_thunk<hkbStateMachine_NullGuard>(Relocation{ REL::ID(59373), 0x2d0 });

    }


}