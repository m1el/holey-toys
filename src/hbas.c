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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
//
#include "bytevec.c"
//
#include "args.c"
#include "instructions.c"
//
#include "hash.c"
//
#include "register.c"
#include "token.c"
//
#include "einfo.h"

void hd(char *data, size_t len) {
    for (size_t ii = 0; ii < len; ii += 1) {
        if (ii > 0 && (ii & 15) == 0) {
            printf("\n");
        }
        printf("%02x", (uint8_t)data[ii]);
    }
    printf("\n");
}

#define MIN_SIZE 4096

int slurp(FILE *fd, ByteVec *out) {
    ByteVec rv = {malloc(MIN_SIZE), MIN_SIZE, 0};
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

size_t label_lookup(LabelVec *labels, char *name, size_t len) {
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

// safety: assumes the buffer has enough place for specified integer size.
// `sign` is a bitset, where bit `1` indicates that value accepts a signed int,
// and bit `2` indicates that value accepts an unsigned int.
AsmError push_int_le(char *buf, uint64_t val, size_t size, uint8_t sign) {
    // Unsigned integers must have all upper bits set to zero. To check this,
    // we shift the value right by the integer size and verify it equals zero.
    int valid_uint = (val >> (size * 8)) == 0;

    // For signed integers, the sign-extended high bits must match the sign bit.
    // By shifting right by one less than the total bit size (size * 8 - 1),
    // we isolate the sign bit and any sign-extended bits. For a value fitting
    // in the signed range, this operation results in either 0 (for non-negative
    // values) or -1 (for negative values due to sign extension).
    int64_t int_shifted = ((int64_t)val) >> (size * 8 - 1);

    // To unify the check for both positive and negative cases, we adjust
    // non-zero values (-1) by incrementing by 1.  This turns -1 into 0,
    // enabling a single check for 0 to validate both cases.  This adjustment
    // simplifies the validation logic, allowing us to use a single condition to
    // check for proper sign extension or zero extension in the original value.
    int_shifted += int_shifted != 0;

    // A valid signed integer will have `int_shifted` equal to 0
    // after adjustment, indicating proper sign extension.
    int valid_int = int_shifted == 0;

    // Validity bitmask to represents whether the value
    // fits as signed, unsigned, or both.
    int validity = valid_int | (valid_uint << 1);

    // If the value's validity doesn't match the `sign` requirements,
    // we report an overflow.
    if ((validity & sign) == 0) {
        return ErrImmediateOverflow;
    }

    // Write out the bytes of the integer to the buffer in little-endian order,
    // starting with the lowest byte first.
    for (size_t ii = 0; ii < size; ii += 1) {
        buf[ii] = val & 0xff;
        val >>= 8;
    }
    return ErrOk;
}

AsmError assemble_instr(InstHt ht, char *input, size_t len, Token *tok,
                        ByteVec *rv, HoleVec *holes) {
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
        if (tok->kind == TokNeg) {
            *tok = token(input, len, tok->start + tok->len);
            if (tok->kind != TokNumber) {
                return ErrTriedNegateNonNumber;
            }
            is_negative -= 1;
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
                    if (ensure_push((ByteVec *)holes, sizeof(Hole), 1) != 0) {
                        return ErrOutOfMemory;
                    }
                    holes->buf[holes->len] = (Hole){
                        .location = rv->len,
                        .origin = inst_start,
                        .str = &input[tok->start],
                        .len = tok->len,
                        .size = (size_t)meta.size,
                    };
                    holes->len += 1;
                    num_to_write = 0;
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
                int64_t tmp = -(int64_t)num_to_write;
                if (tmp > 0) {
                    return ErrBadNumOverflow;
                }
                num_to_write = (uint64_t)tmp;
            }
            AsmError err = push_int_le(&rv->buf[rv->len], num_to_write,
                                       meta.size, meta.sign);
            if (err != ErrOk) {
                return err;
            }
            rv->len += meta.size;
        }
    }

    return ErrOk;
}

AsmError assemble(InstHt ht, char *input, size_t len, ByteVec *out,
                  EInfo *einfo) {
    ByteVec rv = {malloc(MIN_SIZE), MIN_SIZE, 0};
    HoleVec holes = {malloc(MIN_SIZE * sizeof(Hole)), MIN_SIZE, 0};
    LabelVec labels = {malloc(MIN_SIZE * sizeof(Label)), MIN_SIZE, 0};
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
                if (ensure_push((ByteVec *)&labels, sizeof(Label), 1) != 0) {
                    err = ErrOutOfMemory;
                    goto end;
                }
                size_t idx = label_lookup(&labels, &input[tok.start], tok.len);
                if (idx != INVALID) {
                    err = ErrDuplicateLabel;
                    goto end;
                }
                labels.buf[labels.len] = (Label){
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
                err = assemble_instr(ht, input, len, &tok, &rv, &holes);
                pos = tok.start + tok.len;
                if (err != 0) {
                    goto end;
                }
            }
            continue;
        }
        err = ErrUnexpectedToken;
        goto end;
    }

    for (size_t ii = 0; ii < holes.len; ii += 1) {
        Hole *hole = &holes.buf[ii];
        size_t idx = label_lookup(&labels, hole->str, hole->len);
        uint64_t num_to_write = labels.buf[idx].location;
        uint8_t sign = 2;
        if (hole->size != 8) {
            sign = 1;
            num_to_write -= hole->origin;
        }
        err = push_int_le(&rv.buf[hole->location], num_to_write, hole->size,
                          sign);
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
        fprintf(stderr,
                "failed to assemble, %s, line=%zu, col=%zu token=%.*s\n",
                ERRORS[err], einfo.line, column, (int)einfo.token.len,
                &input.buf[einfo.token.start]);
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
