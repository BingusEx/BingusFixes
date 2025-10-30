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



    struct BSEffectShaderSub {

        //AE ID: 107529 AE Offset: 0x0
        //a2 is null
        //happens thanks to the armorunlimited mod the chance is random but is related to
        //membrane shaders/effect shaders.
        //the pointer passed in a2 is probably a smart pointer or something else thats refcounted and managed by other threads.
        //Simply checking if a2 is null is not enough as its possible for the property to be freed after the check has passed.
        //need to implement an asm null guard for each individual use of the ptr because of this.
        //the SEH exception handler is works but its "one of the x of all time" levels of a bad idea to do.

        //Theory 2, The game has a ref counted pointer for the lighting property (or an object that contains a concrete implementation of it).
        //When it wants to apply an effect shader on an armor piece in a slot that has virtual biped slots created by armorulimited,
		//the game first handels the real slot, assumes the job is done and frees the object, but then when it tries to apply the effect shader on the extra biped slot the object has been alreadty freed.
		//This free is done by another thread so its not possible to just detour an if check prologue.

        static void __fastcall thunk(uint64_t* a1, BSLightingShaderProperty* a2, void* r8_0, void* a4, void* a3, NiAlphaProperty* a6, void* a7, void* a8, char a9) {
            __try {
                if (!a1 || !a2) {
                    return;
                }

                func(a1, a2, r8_0, a4, a3, a6, a7, a8, a9);
            }
            __except (EXCEPTION_CONTINUE_EXECUTION) {}
        }

        FUNCTYPE_DETOUR func;

    };

    inline void Install() {

        auto& Trampoline = SKSE::GetTrampoline();
        Trampoline.create(256);

        Hooks::stl::write_xbyak_thunk<ScaleformSub_NullGuard>(Relocation{ REL::ID(87792), 0x10f });
        Hooks::stl::write_xbyak_thunk<hkbStateMachine_NullGuard>(Relocation{ REL::ID(59373), 0x237 });
        Hooks::stl::write_xbyak_thunk<hkbStateMachine_NullGuard>(Relocation{ REL::ID(59373), 0x2d0 });
        Hooks::stl::write_detour<BSEffectShaderSub>(RelocationID(NULL, 107529));
    }


}