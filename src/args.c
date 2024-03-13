typedef struct ArgMeta_s {
    char chr;
    uint8_t size;
    // This is a bitset of acceptable overflow states,
    // where accept signed = 1, accept unsigned = 2.
    // 1 -> signed, 2 -> unsigned, 3 -> whatever
    uint8_t sign;
    uint8_t rel;
} ArgMeta;
const ArgMeta ARGS[] = {
    {'R', 1, 2, 0}, {'1', 1, 3, 0}, {'b', 1, 1, 0}, {'B', 1, 2, 0},
    {'2', 2, 3, 0}, {'o', 2, 1, 1}, {'h', 2, 1, 0}, {'H', 2, 2, 0},
    {'4', 4, 3, 0}, {'w', 4, 1, 0}, {'O', 4, 1, 1}, {'W', 4, 2, 0},
    {'8', 8, 3, 0}, {'d', 8, 1, 0}, {'D', 8, 2, 0}, {0},
};

typedef enum Operands_e {
    Empty = 0,
    R,
    RR,
    RRR,
    RRRR,
    Rx8,
    Rx16,
    Rx32,
    Rx64,
    RRx8,
    RRx16,
    RRx32,
    RRx64,
    RRs32,
    RRs64,
    RRu8,
    RRu16,
    RRu64,
    r16,
    r32,
    RRr16,
    RRr32,
    RRr16u16,
    RRr32u16,
    RRu64u16,
} Operands;
// R -> register,
// 1 -> Xi8, 2 -> Xi16, 4 -> Xi32, 8 -> Xi64,
// b -> Si8, h -> Si16, w -> Si32, d -> Si64,
// B -> Ui8, H -> Ui16, W -> Ui32, D -> Ui64,
// o -> 16 bit relative offset,
// O -> 32 bit relative offset,

const char *TYPE_STR[] = {
    "",    "R",   "RR",  "RRR", "RRRR", "R1",   "R2",   "R4",  "R8",
    "RR1", "RR2", "RR4", "RR8", "RRw",  "RRd",  "RRB",  "RRH", "RRD",
    "o",   "O",   "RRo", "RRO", "RRoH", "RROH", "RRDH",
};

const size_t NARGS = sizeof(ARGS) / sizeof(ARGS[0]);

static
ArgMeta arg_meta(char arg) {
    for (size_t ii = 0; ii < NARGS; ii += 1) {
        ArgMeta meta = ARGS[ii];
        if (meta.chr == arg) {
            return meta;
        }
    }
    return ARGS[NARGS - 1];
}
