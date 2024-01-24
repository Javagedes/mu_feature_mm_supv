;------------------------------------------------------------------------------ ;
; Copyright (c) 2016 - 2018, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   SmiException.nasm
;
; Abstract:
;
;   Exception handlers used in SM mode
;
;-------------------------------------------------------------------------------

%include "StuffRsbNasm.inc"

extern  ASM_PFX(SmmStmExceptionHandler)
extern  ASM_PFX(SmmStmSetup)
extern  ASM_PFX(SmmStmTeardown)
extern  ASM_PFX(mXdSupported)

%define MSR_IA32_MISC_ENABLE 0x1A0
%define MSR_EFER      0xc0000080
%define MSR_EFER_XD   0x800

    DEFAULT REL
    SECTION .text
;------------------------------------------------------------------------------
; SMM Exception handlers
;------------------------------------------------------------------------------
global ASM_PFX(OnException)
ASM_PFX(OnException):
    mov  rcx, rsp
    add  rsp, -0x28
    call ASM_PFX(SmmStmExceptionHandler)
    add  rsp, 0x28
    mov  ebx, eax
    mov  eax, 4
    vmcall
    jmp $

global ASM_PFX(OnStmSetup)
ASM_PFX(OnStmSetup):
;
; Check XD disable bit
;
    xor     r8, r8
    lea     rax, [ASM_PFX(mXdSupported)]
    mov     al, [rax]
    cmp     al, 0
    jz      @StmXdDone1
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    mov     r8, rdx                    ; save MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2                  ; MSR_IA32_MISC_ENABLE[34]
    jz      .01
    and     dx, 0xFFFB                 ; clear XD Disable bit if it is set
    wrmsr
.01:
    mov     ecx, MSR_EFER
    rdmsr
    or      ax, MSR_EFER_XD            ; enable NXE
    wrmsr
@StmXdDone1:
    push    r8

  add  rsp, -0x20
  call ASM_PFX(SmmStmSetup)
  add  rsp, 0x20

    lea     rax, [ASM_PFX(mXdSupported)]
    mov     al, [rax]
    cmp     al, 0
    jz      .11
    pop     rdx                       ; get saved MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2
    jz      .11
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    or      dx, BIT2                  ; set XD Disable bit if it was set before entering into SMM
    wrmsr

.11:
    StuffRsb64
    rsm

global ASM_PFX(OnStmTeardown)
ASM_PFX(OnStmTeardown):
;
; Check XD disable bit
;
    xor     r8, r8
    lea     rax, [ASM_PFX(mXdSupported)]
    mov     al, [rax]
    cmp     al, 0
    jz      @StmXdDone2
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    mov     r8, rdx                    ; save MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2                  ; MSR_IA32_MISC_ENABLE[34]
    jz      .02
    and     dx, 0xFFFB                 ; clear XD Disable bit if it is set
    wrmsr
.02:
    mov     ecx, MSR_EFER
    rdmsr
    or      ax, MSR_EFER_XD            ; enable NXE
    wrmsr
@StmXdDone2:
    push    r8

  add  rsp, -0x20
  call ASM_PFX(SmmStmTeardown)
  add  rsp, 0x20

    lea     rax, [ASM_PFX(mXdSupported)]
    mov     al, [rax]
    cmp     al, 0
    jz      .12
    pop     rdx                       ; get saved MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2
    jz      .12
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    or      dx, BIT2                  ; set XD Disable bit if it was set before entering into SMM
    wrmsr

.12:
    StuffRsb64
    rsm
