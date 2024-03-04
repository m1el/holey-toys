mnemonics = [
    "un", "tx", "nop", "add8", "add16", "add32", "add64", "sub8", "sub16",
    "sub32", "sub64", "mul8", "mul16", "mul32", "mul64", "and", "or", "xor",
    "slu8", "slu16", "slu32", "slu64", "sru8", "sru16", "sru32", "sru64",
    "srs8", "srs16", "srs32", "srs64", "cmpu", "cmps", "diru8", "diru16",
    "diru32", "diru64", "dirs8", "dirs16", "dirs32", "dirs64", "neg", "not",
    "sxt8", "sxt16", "sxt32", "addi8", "addi16", "addi32", "addi64", "muli8",
    "muli16", "muli32", "muli64", "andi", "ori", "xori", "slui8", "slui16",
    "slui32", "slui64", "srui8", "srui16", "srui32", "srui64", "srsi8",
    "srsi16", "srsi32", "srsi64", "cmpui", "cmpsi", "cp", "swa", "li8", "li16",
    "li32", "li64", "lra", "ld", "st", "ldr", "str", "bmc", "brc", "jmp", "jal",
    "jala", "jeq", "jne", "jltu", "jgtu", "jlts", "jgts", "eca", "ebp",
    "fadd32", "fadd64", "fsub32", "fsub64", "fmul32", "fmul64", "fdiv32",
    "fdiv64", "fma32", "fma64", "fcmplt32", "fcmplt64", "fcmpgt32", "fcmpgt64",
    "itf32", "itf64", "fti32", "fti64", "fc32t64", "fc64t32", "lra16", "ldr16",
    "str16", "jmp16",
]
from collections import Counter
mnemonics = [s.encode('utf-8') for s in mnemonics]

for ii in range(0, 1000000):
    def mh(s):
        h = 0
        mask32 = (1 << 32) - 1
        mul = ii # 0x4F6CDD1D
        for c in s:
            h ^= c * mul
            h *= mul
            h = h & mask32
        return h & 0xffff
    ct = Counter(mh(s) for s in mnemonics)
    # n = sum(1 if c == 2 else 0 for c in ct.values())
    n = 0
    c = ct.most_common(1)[0][1]
    if c == 1 and n == 0:
        print(ii, n)
