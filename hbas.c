/*
Copyright (c) 2024 Igor null <m1el.2027@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hd(char *data, size_t len) {
    for (size_t ii = 0; ii < len; ii += 1) {
        if (ii > 0 && (ii & 15) == 0) {
            printf("\n");
        }
        printf("%02x", (uint8_t)data[ii]);
    }
    printf("\n");
}

typedef enum OpType_e {
    Empty = 0,
    R, RR, RRR, RRRR,
    Rx8,  Rx16,  Rx32,  Rx64,
    RRx8, RRx16, RRx32, RRx64,
    RRs32, RRs64,
    RRu8, RRu16, RRu64,
    r16, r32,
    RRr16, RRr32,
    RRr16u16,
    RRr32u16,
    RRu64u16,
} OpType;
// R -> register,
// 1 -> Xi8, 2 -> Xi16, 4 -> Xi32, 8 -> Xi64,
// b -> Si8, h -> Si16, w -> Si32, d -> Si64,
// B -> Ui8, H -> Ui16, W -> Ui32, D -> Ui64,
// o -> 16 bit relative offset,
// O -> 32 bit relative offset,

const char *TYPE_STR[] = {
    "",
    "R", "RR", "RRR", "RRRR",
    "R1",  "R2",  "R4",  "R8",
    "RR1", "RR2", "RR4", "RR8",
    "RRw", "RRd",
    "RRB", "RRH", "RRD",
    "o", "O",
    "RRo", "RRO",
    "RRoH",
    "RROH",
    "RRDH",
};

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
    { 'R', 1, 2, 0 },
    { '1', 1, 3, 0 },
    { 'b', 1, 1, 0 },
    { 'B', 1, 2, 0 },
    { '2', 2, 3, 0 },
    { 'o', 2, 1, 1 },
    { 'h', 2, 1, 0 },
    { 'H', 2, 2, 0 },
    { '4', 4, 3, 0 },
    { 'w', 4, 1, 0 },
    { 'O', 4, 1, 1 },
    { 'W', 4, 2, 0 },
    { '8', 8, 3, 0 },
    { 'd', 8, 1, 0 },
    { 'D', 8, 2, 0 },
    { 0 },
};
const size_t NARGS = sizeof(ARGS) / sizeof(ARGS[0]);
ArgMeta arg_meta(char arg) {
    for (size_t ii = 0; ii < NARGS; ii += 1) {
        ArgMeta meta = ARGS[ii];
        if (meta.chr == arg) {
            return meta;
        } 
    }
    return ARGS[NARGS - 1];
}

typedef struct InstDesc_s {
    char *mnemonic;
    unsigned char opcode;
    OpType type;
} InstDesc;

const InstDesc INST[] = {
    { "un",     0x00, Empty },
    { "tx",     0x01, Empty },
    { "nop",    0x02, Empty },
    { "add8",   0x03, RRR },
    { "add16",  0x04, RRR },
    { "add32",  0x05, RRR },
    { "add64",  0x06, RRR },
    { "sub8",   0x07, RRR },
    { "sub16",  0x08, RRR },
    { "sub32",  0x09, RRR },
    { "sub64",  0x0A, RRR },
    { "mul8",   0x0B, RRR },
    { "mul16",  0x0C, RRR },
    { "mul32",  0x0D, RRR },
    { "mul64",  0x0E, RRR },
    { "and",    0x0F, RRR },
    { "or",     0x10, RRR },
    { "xor",    0x11, RRR },
    { "slu8",   0x12, RRR },
    { "slu16",  0x13, RRR },
    { "slu32",  0x14, RRR },
    { "slu64",  0x15, RRR },
    { "sru8",   0x16, RRR },
    { "sru16",  0x17, RRR },
    { "sru32",  0x18, RRR },
    { "sru64",  0x19, RRR },
    { "srs8",   0x1A, RRR },
    { "srs16",  0x1B, RRR },
    { "srs32",  0x1C, RRR },
    { "srs64",  0x1D, RRR },
    { "cmpu",   0x1E, RRR },
    { "cmps",   0x1F, RRR },
    { "diru8",  0x20, RRRR },
    { "diru16", 0x21, RRRR },
    { "diru32", 0x22, RRRR },
    { "diru64", 0x23, RRRR },
    { "dirs8",  0x24, RRRR },
    { "dirs16", 0x25, RRRR },
    { "dirs32", 0x26, RRRR },
    { "dirs64", 0x27, RRRR },
    { "neg",    0x28, RR }, 
    { "not",    0x29, RR }, 
    { "sxt8",   0x2A, RR },
    { "sxt16",  0x2B, RR },
    { "sxt32",  0x2C, RR },
    { "addi8",  0x2D, RRx8 },
    { "addi16", 0x2E, RRx16 },
    { "addi32", 0x2F, RRx32 },
    { "addi64", 0x30, RRx64 },
    { "muli8",  0x31, RRx8 },
    { "muli16", 0x32, RRx16 },
    { "muli32", 0x33, RRx32 },
    { "muli64", 0x34, RRx64 },
    { "andi",   0x35, RRx64 },
    { "ori",    0x36, RRx64 },
    { "xori",   0x37, RRx64 },
    { "slui8",  0x38, RRu8 },
    { "slui16", 0x39, RRu8 },
    { "slui32", 0x3A, RRu8 },
    { "slui64", 0x3B, RRu8 },
    { "srui8",  0x3C, RRu8 },
    { "srui16", 0x3D, RRu8 },
    { "srui32", 0x3E, RRu8 },
    { "srui64", 0x3F, RRu8 },
    { "srsi8",  0x40, RRu8 },
    { "srsi16", 0x41, RRu8 },
    { "srsi32", 0x42, RRu8 },
    { "srsi64", 0x43, RRu8 },
    { "cmpui",  0x44, RRu64 },
    { "cmpsi",  0x45, RRs64 },
    { "cp",     0x46, RR },
    { "swa",    0x47, RR },
    { "li8",    0x48, Rx8 },
    { "li16",   0x49, Rx16 },
    { "li32",   0x4A, Rx32 },
    { "li64",   0x4B, Rx64 },
    { "lra",    0x4C, RRr32 },
    { "ld",     0x4D, RRu64u16 },
    { "st",     0x4E, RRu64u16 },
    { "ldr",    0x4F, RRr32u16 },
    { "str",    0x50, RRr32u16 },
    { "bmc",    0x51, RRu16 },
    { "brc",    0x52, RRu8 },
    { "jmp",    0x53, r32 },
    { "jal",    0x54, RRr32 },
    { "jala",   0x55, RRu64 },
    { "jeq",    0x56, RRr16 },
    { "jne",    0x57, RRr16 },
    { "jltu",   0x58, RRr16 },
    { "jgtu",   0x59, RRr16 },
    { "jlts",   0x5A, RRr16 },
    { "jgts",   0x5B, RRr16 },
    { "eca",    0x5C, Empty },
    { "ebp",    0x5D, Empty },
    { "fadd32", 0x5E, RRR },
    { "fadd64", 0x5F, RRR },
    { "fsub32", 0x60, RRR },
    { "fsub64", 0x61, RRR },
    { "fmul32", 0x62, RRR },
    { "fmul64", 0x63, RRR },
    { "fdiv32", 0x64, RRR },
    { "fdiv64", 0x65, RRR },
    { "fma32",  0x66, RRRR },
    { "fma64",  0x67, RRRR },
    { "fcmplt32", 0x6A, RRR },
    { "fcmplt64", 0x6B, RRR },
    { "fcmpgt32", 0x6C, RRR },
    { "fcmpgt64", 0x6D, RRR },
    { "itf32",   0x6E, RR },
    { "itf64",   0x6F, RR },
    { "fti32",   0x70, RRu8 },
    { "fti64",   0x71, RRu8 },
    { "fc32t64", 0x72, RR },
    { "fc64t32", 0x73, RR },
    { "lra16",   0x74, RRr16 },
    { "ldr16",   0x75, RRr16u16 },
    { "str16",   0x76, RRr16u16 },
    { "jmp16",   0x77, r16 },
};

const size_t INST_CNT = sizeof(INST) / sizeof(INST[0]);
const size_t INVALID = ~(size_t)0;
size_t inst_find(const char *mnemonic, size_t len) {
    for (size_t ii = 0; ii < INST_CNT; ii += 1) {
        const char *entry = INST[ii].mnemonic;
        if (strncmp(entry, mnemonic, len) == 0 && entry[len] == '\0') {
            return ii;
        }
    }
    return INVALID;
}

// Instruction Hash table, for faster lookups
typedef struct InstHtNode_s {
    uint8_t index1;
    uint8_t index2;
} InstHtNode;
typedef InstHtNode *InstHt;

uint32_t inst_hash(const char *s, size_t len) {
    uint32_t hash = 0;
    uint32_t mul = 75;
    for (size_t ii = 0; ii < len; ii += 1) {
        hash ^= s[ii] * mul;
        hash *= mul;
    }
    return hash;
}

InstHt build_lookup(void) {
    const size_t size = 256;
    InstHt table = (InstHt)malloc(size * sizeof(InstHtNode));
    if (table == NULL) {
        return table;
    }
    for (size_t ii = 0; ii < size; ii += 1) {
        table[ii] = (InstHtNode) { 0xff, 0xff };
    }
    for (size_t ii = 0; ii < INST_CNT; ii += 1) {
        const char *mnemonic = INST[ii].mnemonic;
        uint32_t hash = inst_hash(mnemonic, strlen(mnemonic));
        InstHtNode *node = &table[hash & 0xff];
        if (node->index1 == 0xff) {
            node->index1 = ii;
        } else if (node->index2 == 0xff) {
            node->index2 = ii;
        } else {
            fprintf(stderr, "more than 1 collision in hash table\n");
            exit(1);
        }
    }
    return table;
}

size_t inst_lookup(InstHt ht, const char *s, size_t len) {
    uint32_t hash = inst_hash(s, len);
    uint8_t *node = (uint8_t*)&ht[(size_t)(hash & 0xff)];
    for (size_t ii = 0; ii < 2; ii += 1) {
        size_t idx = (size_t)node[ii];
        if (idx == 0xff) {
            break;
        }
        const char *mnemonic = INST[idx].mnemonic;
        if (strncmp(s, mnemonic, len) == 0 && mnemonic[len] == 0) {
            return idx;
        }
    }
    return INVALID;
}

typedef enum AsmError_e {
    ErrOk = 0,
    ErrBadRegister,
    ErrImmediateOverflow,
    ErrInvalidToken,
    ErrBadArgumentMeta,
    ErrNeedCommaAfterArgument,
    ErrLabelImmediate,
    ErrNumberImmediate,
    ErrBadNumOverflow,
    ErrBadNumDigit,
    ErrBadNumNoDigit,
    ErrLabelAfterLabel,
    ErrOutOfMemory,
    ErrDuplicateLabel,
    ErrTrailingLine,
    ErrNeedDirectiveAfterDot,
    ErrDirectiveNotImplemented,
} AsmError;
char *ERRORS[] = {
    "Success",
    "Bad register name",
    "Immediate integer OR relative offset overflow",
    "Invalid token",
    "Bad argument char? (blame developer of this program)",
    "Expected comma after the argument, got something else",
    "Label immediate needs label or number",
    "Immediate needs to be a number",
    "Bad number: u64 overflow",
    "Bad number: encountered bad gidit",
    "Bad number: no digits presented after the suffix",
    "Encountered label after label",
    "Out of Memory",
    "Duplicate label",
    "Encountered trailing identifier after instruction",
    "Expected directive after dot",
    "Directive is not implemented",
};

typedef struct ByteVec_s {
    char *buf;
    size_t cap;
    size_t len;
} ByteVec;

AsmError ensure_push(ByteVec *vec, size_t el_size, size_t extra) {
    while (vec->len + extra > vec->cap) {
        vec->cap *= 2;
        // multiply overflow
        if ((~(size_t)0) / el_size < vec->cap) {
            return ErrOutOfMemory;
        }
        vec->buf = realloc(vec->buf, el_size * vec->cap);
        if (vec->buf == NULL) {
            vec->cap = 0;
            return ErrOutOfMemory;
        }
    }
    return 0;
}

#define MIN_SIZE 4096

int slurp(FILE *fd, ByteVec *out) {
    ByteVec rv = { malloc(MIN_SIZE), MIN_SIZE, 0 };
    size_t bread = 1;
    int err = 0;
    if (rv.buf == NULL) {
        rv.cap = 0;
        err = ErrOutOfMemory;
        bread = 0;
    }
    while (bread > 0) {
        if (ensure_push(&rv, 1, 1) != 0) {
            err = ErrOutOfMemory;
            break;
        }
        bread = fread(&rv.buf[rv.len], 1, rv.cap - rv.len, fd);
        rv.len += bread;
    }
    *out = rv;
    if (err == 0) {
        err = ferror(fd);
    }
    return err;
}

typedef enum TokenKind_e {
    TokInvalid = '!',
    TokEOF = '$',
    TokIdent = 'A',
    TokNeg = '-',
    TokNumber = '0',
    TokBadNumber = '9',
    TokComma = ',',
    TokDot = '.',
    TokColon = ':',
    TokComment = ';',
    TokNewline = 'n',
} TokenKind;
typedef struct Token_s {
    TokenKind kind;
    size_t start;
    size_t len;
    uint64_t num;
} Token;

Token token_ident(char *input, size_t len, size_t pos) {
    size_t start = pos;
    while (pos < len) {
        char chr = input[pos];
        char chru = chr & ~0x20;
        int good = chr == '_'
            || (chr >= '0' && chr <= '9')
            || (chru >= 'A' && chru <= 'Z');
        if (!good) {
            break;
        }
        pos += 1;
    }
    return (Token) { TokIdent, start, pos - start, 0 };
}

Token token_number(char *input, size_t len, size_t pos) {
    char *ptr = &input[pos];
    char next = '\0';
    size_t start = pos;
    size_t digits = 0;
    uint64_t base = 10;
    uint64_t rv = 0;
    uint64_t pre_overflow;
    AsmError bad_num = ErrOk;

    if (pos + 1 < len) {
        next = ptr[1] & ~0x20;
    }

    if (input[pos] == '0') {
        if (next == 'X') {
            base = 16;
            pos += 2;
        } else if (next == 'D') {
            base = 10;
            pos += 2;
        } else if (next == 'O') {
            base = 8;
            pos += 2;
        } else if (next == 'B') {
            base = 2;
            pos += 2;
        }
    }
    pre_overflow = (~(size_t)0) / base;
    // valid: "0x_0", "0_"
    // invalid: "0x_"
    while (pos < len) {
        uint64_t digit;
        uint64_t next;
        char chr = input[pos];
        char chru = chr & ~0x20;
        if (chr == '_') { pos += 1; continue; }
        digit = (uint64_t)chr - (uint64_t)'0';
        if (digit >= 10) {
            digit = (uint64_t)chru - (uint64_t)('A' - 10);
        }
        if (digit >= base) {
            if (chr >= '0' && chr <= '9') {
                bad_num = ErrBadNumDigit;
            } else if (chru >= 'A' && chru <= 'Z') {
                bad_num = ErrBadNumDigit;
            }
            break;
        }

        pos += 1;
        digits += 1;

        next = rv * base + digit;
        if (rv > pre_overflow || next < rv) {
            bad_num = ErrBadNumOverflow;
            break;
        }
        rv = next;
    }

    if (digits == 0) {
        bad_num = ErrBadNumNoDigit;
    }

    if (bad_num) {
        return (Token) { TokBadNumber, start, pos - start, bad_num };
    } else {
        return (Token) { TokNumber, start, pos - start, rv };
    }
}

Token token(char *input, size_t len, size_t pos) {
    char chr, chru;
    char *ptr = &input[pos];
    while (pos < len && (input[pos] == ' ' || input[pos] == '\t')) {
        pos += 1;
    }
    if (pos == len) {
        return (Token) { TokEOF, pos, 0, 0 };
    }
    ptr = &input[pos];
    chr = *ptr;
    if (chr == ',' || chr == '-' || chr == '.' || chr == ':') {
        return (Token) { (TokenKind)chr, pos, 1, 0 };
    }
    if (chr == '\n') {
        return (Token) { TokNewline, pos, 1, 0 };
    }
    if (chr == '\r') {
        if (pos + 1 < len && ptr[1] == '\n') {
            return (Token) { TokNewline, pos, 2, 0 };
        }
        return (Token) { TokNewline, pos, 1, 0 };
    }
    if (chr == ';') {
        size_t clen = 1;
        while (pos + clen < len && ptr[clen] != '\n' && ptr[clen] != '\r') {
            clen += 1;
        }
        return (Token) { TokComment, pos, clen, 0 };
    }
    if (chr >= '0' && chr <= '9') {
        return token_number(input, len, pos);
    }
    chru = chr & ~0x20;
    if (chr == '_' || (chru >= 'A' && chru <= 'Z')) {
        return token_ident(input, len, pos);
    }
    return (Token) { TokInvalid, pos, 1, 0 };
}

typedef struct Hole_s {
    size_t location;
    size_t origin;
    char *str;
    size_t len;
    size_t size;
} Hole;
typedef struct HoleVec_s {
    Hole *buf;
    size_t cap;
    size_t len;
} HoleVec;
typedef struct Label_s {
    size_t location;
    char *str;
    size_t len;
} Label;
typedef struct LabelVec_s {
    Label *buf;
    size_t cap;
    size_t len;
} LabelVec;

size_t label_lookup(LabelVec *labels, char* name, size_t len) {
    size_t nlabels = labels->len;
    Label *buf = labels->buf;
    for (size_t ii = 0; ii < nlabels; ii += 1) {
        if (len == buf->len && strncmp(buf->str, name, len) == 0) {
            return ii;
        } 
        buf += 1;
    }
    return INVALID;
}

int parse_register(char *name, size_t len) {
    if (name[0] != 'r') {
        return 256; // Register name should start with 'r'
    }
    if (len > 4) {
        return 256; // Register name too long
    }
    uint16_t rv = 0;
    if (len > 2 && name[1] == '0') {
        return 256; // Extra zero suffix
    }
    for (size_t ii = 1; ii < len; ii += 1) {
        char chr = name[ii];
        if (!(chr >= '0' && chr <= '9')) {
            return 256; // Register name must only contain numbers
        }
        rv = rv * 10 + (chr - '0');
    }
    if (rv > 255) {
        return 256; // Register number too large
    }
    return (int)rv;
}

// safety: assumes the buffer has enough place for specified integer size
AsmError push_int_le(char *buf, uint64_t val, size_t size, uint8_t sign) {
    int valid_uint = val >> (size * 8) == 0;
    int64_t int_shifted = ((int64_t)val) >> (size * 8 - 1);
    int valid_int = int_shifted == 0 || (~int_shifted) == 0;
    // Note: this assumes the format for `sign` is a bitset.
    int validity = valid_int | (valid_uint << 1);
    if ((validity & sign) == 0) {
        return ErrImmediateOverflow;
    }
    for (size_t ii = 0; ii < size; ii += 1) {
        buf[ii] = val & 0xff;
        val >>= 8;
    }
    return ErrOk;
}

AsmError assemble_instr(
    InstHt ht, char *input, size_t len, Token *tok,
    ByteVec *rv, HoleVec *holes, LabelVec *labels
) {
    const InstDesc *inst;
    const char *type_str;
    size_t nargs;
    size_t size;
    size_t idx = inst_lookup(ht, &input[tok->start], tok->len);
    size_t inst_start = rv->len;
    if (idx == INVALID) {
        return ErrInvalidToken;
    }
    inst = &INST[idx];
    type_str = TYPE_STR[inst->type];
    nargs = strlen(type_str);
    size = 1;
    for (size_t ii = 0; ii < nargs; ii += 1) {
        char chr = type_str[ii];
        ArgMeta meta = arg_meta(chr);
        if (meta.chr == 0) {
            return ErrBadArgumentMeta;
        }
        size += meta.size;
    }
    if (ensure_push(rv, 1, size) != 0) {
        return ErrOutOfMemory;
    }
    rv->buf[rv->len] = inst->opcode;
    rv->len += 1;
    for (size_t ii = 0; ii < nargs; ii += 1) {
        if (ii > 0) {
            *tok = token(input, len, tok->start + tok->len);
            if (tok->kind != TokComma) {
                return ErrNeedCommaAfterArgument;
            }
        }
        char chr = type_str[ii];
        ArgMeta meta = arg_meta(chr);
        uint64_t is_negative = 0;
        *tok = token(input, len, tok->start + tok->len);
        while (!is_negative) {
            if (tok->kind == TokNeg) {
                *tok = token(input, len, tok->start + tok->len);
                is_negative = ~(uint64_t)0;
            } else {
                break;
            }
        }
        if (chr == 'R') {
            int reg = parse_register(&input[tok->start], tok->len);
            if (reg > 255) {
                return ErrBadRegister;
            }
            rv->buf[rv->len] = (char)(reg & 0xff);
            rv->len += 1;
        } else {
            uint64_t num_to_write;
            if (meta.rel == 1 || meta.size == 8) {
                if (tok->kind == TokIdent) {
                    size_t idx = label_lookup(labels, &input[tok->start], tok->len);
                    if (idx == INVALID) {
                        if (ensure_push((ByteVec*)holes, 1, sizeof(Hole)) != 0) {
                            return ErrOutOfMemory;
                        }
                        holes->buf[holes->len] = (Hole) {
                            .location = rv->len,
                            .origin = inst_start,
                            .str = &input[tok->start],
                            .len = tok->len,
                            .size = (size_t)meta.size,
                        };
                        holes->len += 1;
                        num_to_write = 0;
                    } else {
                        num_to_write = labels->buf[idx].location;
                        if (meta.size != 8) {
                            num_to_write -= inst_start;
                        }
                    }
                } else if (tok->kind == TokNumber) {
                    num_to_write = tok->num;
                } else {
                    return ErrLabelImmediate;
                }
            } else if (tok->kind == TokNumber) {
                num_to_write = tok->num;
            } else {
                return ErrNumberImmediate;
            }
            // num_to_write = num_to_write ^ is_negative - is_negative;
            if (is_negative) {
                num_to_write = (uint64_t)(-(int64_t)num_to_write);
            }
            AsmError err = push_int_le(
                &rv->buf[rv->len], num_to_write, meta.size, meta.sign
            );
            if (err != 0) {
                return err;
            }
            rv->len += meta.size;
        }
    }

    return 0;
}

typedef struct EInfo_s {
    Token token;
    size_t line;
    size_t line_start;
} EInfo;

AsmError assemble(InstHt ht, char *input, size_t len, ByteVec *out, EInfo *einfo) {
    ByteVec rv = { malloc(MIN_SIZE), MIN_SIZE, 0 };
    HoleVec holes = { malloc(MIN_SIZE * sizeof(Hole)), MIN_SIZE, 0 };
    LabelVec labels = { malloc(MIN_SIZE * sizeof(Label)), MIN_SIZE, 0 };
    size_t line = 0;
    size_t line_start = 0;
    size_t pos = 0;
    // init=0, label=1, instruction=2, comment=3, newline -> 0
    size_t line_state = 0;
    AsmError err = ErrOk;

    while (1) {
        Token tok = token(input, len, pos);
        einfo->token = tok;
        pos = tok.start + tok.len;
        if (tok.kind == TokInvalid || tok.kind == TokBadNumber) {
            if (tok.num) {
                err = (AsmError)tok.num;
            } else {
                err = ErrInvalidToken;
            }
            break;
        }
        if (tok.kind == TokEOF) {
            break;
        }
        if (tok.kind == TokComment) {
            line_state = 3;
            continue;
        }
        if (tok.kind == TokNewline) {
            line += 1;
            line_start = tok.start + tok.len;
            line_state = 0;
            continue;
        }
        if (tok.kind == TokDot) {
            Token next = token(input, len, pos);
            if (next.kind == TokIdent) {
                err = ErrDirectiveNotImplemented;
                goto end;
            } else {
                err = ErrNeedDirectiveAfterDot;
                goto end;
            }
            continue;
        }
        if (tok.kind == TokIdent) {
            Token next = token(input, len, pos);
            if (next.kind == TokColon) {
                // Label
                pos = next.start + next.len;
                if (line_state >= 1) {
                    err = ErrLabelAfterLabel;
                    einfo->token = next;
                    goto end;
                }
                line_state = 1;
                if (ensure_push((ByteVec*)&labels, sizeof(Label), 1) != 0) {
                    err = ErrOutOfMemory;
                    goto end;
                }
                size_t idx = label_lookup(&labels, &input[tok.start], tok.len);
                if (idx != INVALID) {
                    err = ErrDuplicateLabel;
                    goto end;
                }
                labels.buf[labels.len] = (Label) {
                    .location = rv.len,
                    .str = &input[tok.start],
                    .len = tok.len,
                };
                labels.len += 1;
            } else {
                // Instruction
                if (line_state >= 2) {
                    err = ErrTrailingLine;
                    goto end;
                }
                line_state = 2;
                err = assemble_instr(
                    ht, input, len, &tok,
                    &rv, &holes, &labels
                );
                pos = tok.start + tok.len;
                if (err != 0) {
                    goto end;
                }
            }
            continue;
        }
    }

    for (size_t ii = 0; ii < holes.len; ii += 1) {
        Hole *hole = &holes.buf[ii];
        size_t idx = label_lookup(&labels, hole->str, hole->len);
        uint64_t num_to_write = labels.buf[idx].location;
        uint8_t sign = 1;
        if (hole->size != 8) {
            sign = 2;
            num_to_write -= hole->origin;
        }
        err = push_int_le(
            &rv.buf[hole->location], num_to_write, hole->size, sign
        );
        if (err != 0) {
            goto end;
        }
    }
    end:
    free(holes.buf);
    free(labels.buf);
    *out = rv;
    einfo->line = line + 1;
    einfo->line_start = line_start;
    return err;
}

int main(int argc, char **argv) {
    int hex_out = 0;
    if (argc >= 2 && strcmp(argv[1], "--hex") == 0) {
        hex_out = 1;
    }

    int err = 0;
    InstHt ht = NULL;
    ByteVec input;


    err = slurp(stdin, &input);
    if (err != 0) {
        fprintf(stderr, "failed to read the file: %d\n", err);
        goto done;
    }
    ht = build_lookup();
    if (ht == NULL) {
        err = ErrOutOfMemory;
        fprintf(stderr, "failed to init hash table: %d\n", err);
        goto done;
    }

    ByteVec out;
    EInfo einfo;
    err = assemble(ht, input.buf, input.len, &out, &einfo);
    if (err != 0) {
        size_t column = einfo.token.start - einfo.line_start + 1;
        fprintf(stderr, "failed to assemble, %s, line=%zu, col=%zu token=",
            ERRORS[err], einfo.line, column);
        fwrite(&input.buf[einfo.token.start], 1, einfo.token.len, stderr);
        fprintf(stderr, "\n");
        goto done;
    }
    if (hex_out) {
        hd(out.buf, out.len);
    } else {
        fwrite(out.buf, 1, out.len, stdout);
    }

    done:
    free(ht);
    free(input.buf);
    free(out.buf);
    return err;
}
