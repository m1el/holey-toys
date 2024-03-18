jmp entry

puts:
; Write string to console
;  r2: [IN] *const u8  String pointer
;  r3: [IN] usize      String length

    li8     r1, 0x1         ; Write syscall
    brc     r2, r3, 2       ; Copy parameters
    li8     r2, 0x1         ; STDOUT
    eca

    jal     r0, r31, 0

gets:
; Read string until end of buffer or LF
;  r2: [IN] *mut u8    Buffer
;  r3: [IN] usize      Buffer length

    ; Register allocations:
    ;  r33: *mut u8    Buffer end
    ;  r34: u8         Immediate char
    ;  r35: u8         Const [0x0A = LF]

    li8     r35, 0x0A
    add64   r33, r2, r3

    ; Setup syscall
    li8     r2, 0x1         ; Stdin
    cp      r3, r2
    li8     r4, 0x1         ; Read one char

    jeq     r3, r33, end
    loop:
        li8     r1, 0x1     ; Read syscall
        eca
        addi64  r3, r3, 1
        ld      r34, r3, 0, 1
        jeq     r34, r35, end
        jne     r3, r33, loop
    
    end:
        ; Set copied amount
        sub64   r1, r33, r3
        addi64  r1, r1, -1
        jal     r0, r31, 0

alloc_pages:
; Allocate pages
;  r1: [OUT] *mut u8   Pointer to page
;  r2: [IN]  u16       Page count

    muli16  r3, r2, 4096    ; page count
    li8     r1, 0x9         ; mmap syscall
    li8     r2, 0x0         ; no address set, kernel chosen
    li8     r4, 0x2         ; PROT_WRITE
    li8     r5, 0x20        ; MAP_ANONYMOUS
    li64    r6, -1          ; Doesn't map file
    li8     r7, 0x0         ; Doesn't map file
    eca

    jal     r0, r31, 0

entry:
; Program entrypoint

    ; Register allocations:
    ; r32: *mut u8     Buffer
    ; r36: usize       Read buffer length

    ; Allocate one page (4096 KiB)
    li8     r2, 1
    jal     r31, r0, alloc_pages
    cp      r32, r1

    ; Print message
    lra16   r2, r0, enter_your_name
    li8     r3, 17
    jal     r31, r0, puts

    ; Read name
    cp      r2, r32
    li16    r3, 4096
    jal     r31, r0, gets
    cp      r36, r1

    ; Print your name is
    lra16   r2, r0, your_name_is
    li8     r3, 15
    jal     r31, r0, puts

    ; And now print the name
    cp      r2, r32
    cp      r3, r36
    jal     r31, r0, puts

    tx


enter_your_name:
    .db "Enter your name: "
your_name_is:
    .db "\nYour name is: "