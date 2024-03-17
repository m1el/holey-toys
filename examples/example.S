; holey-bytes vm
; https://git.ablecorp.us/AbleOS/holey-bytes/src/branch/trunk/spec.md
; TODO:
; .origin 0x1000
; 'c' char literals
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
    .db "Hello, w\x6frld\n", 0
hello_string_end:
    .db "hi"
    ; TODO .db 'H', 'e', 'l', 'l', 'o', '\0'
    .align 2
    .dw 0x4546
    .align 4
    .dd 0x4748494a
    .align 8
    .dq 0x5051525354555657
