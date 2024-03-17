    li8 r1, 1
    li8 r2, 1
    lra16 r3, r0, hello_string
    li8 r4, 0x11
    eca
    tx
hello_string:
    .db "Hello, AbleCorp!\n"
