; holey-bytes vm
; https://git.ablecorp.us/AbleOS/holey-bytes/src/branch/trunk/spec.md
; TODO:
; .origin 0x1000
; .align 0x100
; .db "hello"
; .stuct
start:
    jmp end
    un
    ; .db "hello world\n"
    add16 r1, r2, r255
    addi8 r1, r2, -128
    lra r1, r0, start
    jmp start
end:
    tx
