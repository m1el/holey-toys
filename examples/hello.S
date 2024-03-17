    li8 r1, 1     ; 1->sys::write
    li8 r2, 1     ; fildes=stdout
    lra16 r3, r0, hello_string ; buf=hello_string
    li8 r4, 0x11  ; nbyte=0x11
    eca ; sys::write(stdout, hello_string, 0x11)
    tx
hello_string:
    .db "Hello, AbleCorp!\n"
