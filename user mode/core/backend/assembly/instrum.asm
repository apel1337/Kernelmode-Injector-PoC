.code
instrumentation_callback PROC
key:
    nop
    nop
    nop
    nop
    mov rcx, 07fffffffffffh
    pushfq
    push rcx
    push rax
    xor rax, rax
    lea rcx, key
    xchg eax, DWORD PTR [rcx]
    cmp eax, 1
    jz callback_start
    pop rax
    pop rcx
    popfq
    jmp rcx

callback_start:
    pop rax
    pop rcx
    popfq
    mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
    sub     rsp, 04d0h                 ; Alloc stack space for CONTEXT structure
    and     rsp, -010h                 ; RSP must be 16 byte aligned before calls
    mov     rcx, rsp
    call capture_context
    sub rsp, 020h
    mov rdx, rcx
    mov rcx, 07fffffffffffh
    lea rax, shellcode_placeholder
    jmp rax
    int 3 ; Should never reach here

capture_context:
    mov [rcx+078h], rax
    mov [rcx+080h], rcx
    mov [rcx+088h], rdx
    mov [rcx+0B8h], r8
    mov [rcx+0C0h], r9
    mov [rcx+0C8h], r10
    mov [rcx+0D0h], r11
    fxsave DWORD PTR [rcx+0100h]

    mov WORD PTR [rcx+038h], cs
    mov WORD PTR [rcx+03Ah], ds
    mov WORD PTR [rcx+03Ch], es
    mov WORD PTR [rcx+042h], ss
    mov WORD PTR [rcx+03Eh], fs
    mov WORD PTR [rcx+040h], gs

    mov [rcx+090h], rbx
    mov [rcx+0A0h], rbp
    mov [rcx+0A8h], rsi
    mov [rcx+0B0h], rdi
    mov [rcx+0D8h], r12
    mov [rcx+0E0h], r13
    mov [rcx+0E8h], r14
    mov [rcx+0F0h], r15
    stmxcsr DWORD PTR [rcx+034h]
    pushfq
    lea rax, [rsp+010h]
    mov [rcx+098h], rax
    mov rax, [rsp+8]
    mov [rcx+00F8h], rax
    mov eax, [rsp]
    mov [rcx+044h], eax
    mov DWORD PTR [rcx+030h], 010000Fh
    popfq
    ret

shellcode_placeholder:
    nop


sigFuncSz:
int 3
int 3
int 3
int 3
instrumentation_callback ENDP

instrumentation_callbacktwo PROC
key:
    nop
    nop
    nop
    nop
    pushfq
    push rcx
    push rax
    xor rax, rax
    lea rcx, key
    xchg eax, DWORD PTR [rcx]
    cmp eax, 1
    jz callback_start
    pop rax
    pop rcx
    popfq
    jmp r10

callback_start:
    pop rax
    pop rcx
    popfq
    mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
    mov     gs:[2d8h], r10 ; Win10 TEB InstrumentationCallbackPreviousPc
    mov     r10, rcx ; save rcx
    sub     rsp, 04d0h                 ; Alloc stack space for CONTEXT structure
    and     rsp, -010h                 ; RSP must be 16 byte aligned before calls
    mov     rcx, rsp
    call capture_context
    sub rsp, 020h
    mov rdx, rcx
    mov rcx, 07fffffffffffh
    lea rax, shellcode_placeholder
    jmp rax
    int 3 ; Should never reach here

capture_context:
    mov [rcx+078h], rax
    mov [rcx+080h], rcx
    mov [rcx+088h], rdx
    mov [rcx+0B8h], r8
    mov [rcx+0C0h], r9
    mov [rcx+0C8h], r10
    mov [rcx+0D0h], r11
    fxsave DWORD PTR [rcx+0100h]

    mov WORD PTR [rcx+038h], cs
    mov WORD PTR [rcx+03Ah], ds
    mov WORD PTR [rcx+03Ch], es
    mov WORD PTR [rcx+042h], ss
    mov WORD PTR [rcx+03Eh], fs
    mov WORD PTR [rcx+040h], gs

    mov [rcx+090h], rbx
    mov [rcx+0A0h], rbp
    mov [rcx+0A8h], rsi
    mov [rcx+0B0h], rdi
    mov [rcx+0D8h], r12
    mov [rcx+0E0h], r13
    mov [rcx+0E8h], r14
    mov [rcx+0F0h], r15
    stmxcsr DWORD PTR [rcx+034h]
    pushfq
    lea rax, [rsp+010h]
    mov [rcx+098h], rax
    mov rax, [rsp+8]
    mov [rcx+00F8h], rax
    mov eax, [rsp]
    mov [rcx+044h], eax
    mov DWORD PTR [rcx+030h], 010000Fh
    popfq
    ret

shellcode_placeholder:
    nop


sigFuncSz:
int 3
int 3
int 3
int 3
instrumentation_callbacktwo ENDP

END