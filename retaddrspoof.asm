; shoutout to wklsec
; NOT MASM , this file is in NASM syntax and can only be assembled with NASM assembler

[BITS 64]

DEFAULT REL

section .text

; Exported Function Declaration
global RetSpoofCall

RetSpoofCall:
    ; Some space to work with
    sub rsp, 0x100

    ; Store non-volatile registers
    mov [rsp + 0x8], rsi
    mov [rsp + 0x10], rdi
    mov [rsp + 0x18], r12

    ; R10: Function to call
    ; R12: Address of handler
    mov r10, rcx
    lea r12, Fixup

    ; Some more space to work with
    sub rsp, 0x200

    ; Place the gadget into our return address
    mov [rsp], r8

    ; If no arguments, just make the call
    cmp rdx, 0
    je CallFunction

    ; Back these up, we'll need this later
    ; R11: nArgs 
    mov r11, rdx

    ; Move the arguments. Everything to be shifted down 3
    ; It does not matter if we move args to rcx/rdx/r8/r9 if a function doesn't use them, so move them all just in case
    cmp rdx, 4
    mov rcx, r9
    mov rdx, [rsp + 0x300 + 0x28] 
    mov r8, [rsp + 0x300 + 0x30] 
    mov r9, [rsp + 0x300 + 0x38] 
    jle CallFunction

    ; movsq: move QWORD -- RSI -> RDI
    ; rep: repeats RCX amount of times
    ; additional 0x18 offset because technically the 4th arg was in the 7th slot
    mov rax, rcx
    mov rcx, r11
    sub rcx, 4h
    lea rsi, [rsp + 0x28 + 0x18 + 0x300]
    lea rdi, [rsp + 0x28]
    rep movsq

    ; Restore original rcx for patched call
    mov rcx, rax

CallFunction:
    ; Jump to the function we want to call
    jmp r10

Fixup:
    ; Restore non-volatile registers and stack frame
    mov rsi, [rsp + 0x200 + 0x8]
    mov rdi, [rsp + 0x200 + 0x10]
    mov r12, [rsp + 0x200 + 0x18]
    add rsp, 0x300

    ret

