; holey-bytes vm
; https://git.ablecorp.us/AbleOS/holey-bytes/src/branch/trunk/spec.md
; TODO:
; .origin 0x1000
; .align 0x100
; .db "hello"
; .struct
start:
    jmp end
    un
    add16 r1, r2, r255
    addi8 r1, r2, -128
    lra r1, r0, start
    jmp start
end:
    tx
hello_string:
    .db "Hello,\x20world\n", 0
hello_string_end:
    .db 42, "hi", 43
    ; TODO .db 'H', 'e', 'l', 'l', 'o', '\0'
    .align 4
    .dw 42
    .dd 42
    .dq 42
