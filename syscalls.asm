; NOT MASM , this file is in NASM syntax and can only be assembled with NASM assembler
[BITS 64]

DEFAULT REL

extern dwNtCreateUserProccess
extern dwNtReadVirtualMemory
extern dwNtProtectVirtualMemory
extern dwNtTerminateProcess

extern sysCallNtCreateProcess
extern sysCallNtRead
extern sysCallNtProtect
extern sysCallNtTerminate

section .code

; Procedure for NtCreateUserProcess
global SysNtCreateUserProcess
SysNtCreateUserProcess:
    lea r10, [rcx]
    mov eax, dword [dwNtCreateUserProccess]
    jmp qword [sysCallNtCreateProcess]
    ret

; Procedure for NtReadVirtualMemory
global SysNtReadVirtualMemory
SysNtReadVirtualMemory:
    mov r10, rcx
    mov eax, dword [dwNtReadVirtualMemory]
    jmp qword [sysCallNtRead]
    ret

; Procedure for NtProtectVirtualMemory
global SysNtProtectVirtualMemory
SysNtProtectVirtualMemory:
    mov r10, rcx
    mov eax, dword [dwNtProtectVirtualMemory]
    jmp qword [sysCallNtProtect]
    ret

; Procedure for NtTerminateProcess
global SysNtTerminateProcess
SysNtTerminateProcess:
    mov r10, rcx
    mov eax, dword [dwNtTerminateProcess]
    jmp qword [sysCallNtTerminate]
    ret