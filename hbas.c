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
#include <stdint.h>

#include "op.h"
#include "instructions.c"
#include "hash.c"

void hd(char *data, size_t len)
{
    for (size_t ii = 0; ii < len; ii += 1)
    {
        if (ii > 0 && (ii & 15) == 0)
        {
            printf("\n");
        }
        printf("%02x", (uint8_t)data[ii]);
    }
    printf("\n");
}

typedef struct ArgMeta_s
{
    char chr;
    uint8_t size;
    // This is a bitset of acceptable overflow states,
    // where accept signed = 1, accept unsigned = 2.
    // 1 -> signed, 2 -> unsigned, 3 -> whatever
    uint8_t sign;
    uint8_t rel;
} ArgMeta;
const ArgMeta ARGS[] = {
    {'R', 1, 2, 0},
    {'1', 1, 3, 0},
    {'b', 1, 1, 0},
    {'B', 1, 2, 0},
    {'2', 2, 3, 0},
    {'o', 2, 1, 1},
    {'h', 2, 1, 0},
    {'H', 2, 2, 0},
    {'4', 4, 3, 0},
    {'w', 4, 1, 0},
    {'O', 4, 1, 1},
    {'W', 4, 2, 0},
    {'8', 8, 3, 0},
    {'d', 8, 1, 0},
    {'D', 8, 2, 0},
    {0},
};
const size_t NARGS = sizeof(ARGS) / sizeof(ARGS[0]);
ArgMeta arg_meta(char arg)
{
    for (size_t ii = 0; ii < NARGS; ii += 1)
    {
        ArgMeta meta = ARGS[ii];
        if (meta.chr == arg)
        {
            return meta;
        }
    }
    return ARGS[NARGS - 1];
}

typedef enum AsmError_e
{
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
    ErrUnexpectedToken,
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
    "Unexpected token",
};

typedef struct ByteVec_s
{
    char *buf;
    size_t cap;
    size_t len;
} ByteVec;

AsmError ensure_push(ByteVec *vec, size_t el_size, size_t extra)
{
    if (vec->len + extra < vec->len)
    {
        return ErrOutOfMemory;
    }
    while (vec->len + extra > vec->cap)
    {
        if ((~(size_t)0) / 2 < vec->cap)
        {
            return ErrOutOfMemory;
        }
        vec->cap *= 2;
        // multiply overflow
        if ((~(size_t)0) / el_size < vec->cap)
        {
            return ErrOutOfMemory;
        }
        vec->buf = realloc(vec->buf, el_size * vec->cap);
        if (vec->buf == NULL)
        {
            vec->cap = 0;
            return ErrOutOfMemory;
        }
    }
    return 0;
}

#define MIN_SIZE 4096

int slurp(FILE *fd, ByteVec *out)
{
    ByteVec rv = {malloc(MIN_SIZE), MIN_SIZE, 0};
    size_t bread = 1;
    int err = 0;
    if (rv.buf == NULL)
    {
        rv.cap = 0;
        err = ErrOutOfMemory;
        bread = 0;
    }
    while (bread > 0)
    {
        if (ensure_push(&rv, 1, 1) != 0)
        {
            err = ErrOutOfMemory;
            break;
        }
        bread = fread(&rv.buf[rv.len], 1, rv.cap - rv.len, fd);
        rv.len += bread;
    }
    *out = rv;
    if (err == 0)
    {
        err = ferror(fd);
    }
    return err;
}

typedef enum TokenKind_e
{
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
typedef struct Token_s
{
    TokenKind kind;
    size_t start;
    size_t len;
    uint64_t num;
} Token;

Token token_ident(char *input, size_t len, size_t pos)
{
    size_t start = pos;
    while (pos < len)
    {
        char chr = input[pos];
        char chru = chr & ~0x20;
        int good = chr == '_' || (chr >= '0' && chr <= '9') || (chru >= 'A' && chru <= 'Z');
        if (!good)
        {
            break;
        }
        pos += 1;
    }
    return (Token){TokIdent, start, pos - start, 0};
}

Token token_number(char *input, size_t len, size_t pos)
{
    char *ptr = &input[pos];
    char next = '\0';
    size_t start = pos;
    size_t digits = 0;
    uint64_t base = 10;
    uint64_t rv = 0;
    uint64_t pre_overflow;
    AsmError bad_num = ErrOk;

    if (pos + 1 < len)
    {
        next = ptr[1] & ~0x20;
    }

    if (input[pos] == '0')
    {
        if (next == 'X')
        {
            base = 16;
            pos += 2;
        }
        else if (next == 'D')
        {
            base = 10;
            pos += 2;
        }
        else if (next == 'O')
        {
            base = 8;
            pos += 2;
        }
        else if (next == 'B')
        {
            base = 2;
            pos += 2;
        }
    }
    pre_overflow = (~(size_t)0) / base;
    // valid: "0x_0", "0_"
    // invalid: "0x_"
    while (pos < len)
    {
        uint64_t digit;
        uint64_t next;
        char chr = input[pos];
        char chru = chr & ~0x20;
        if (chr == '_')
        {
            pos += 1;
            continue;
        }
        digit = (uint64_t)chr - (uint64_t)'0';
        if (digit >= 10)
        {
            digit = (uint64_t)chru - (uint64_t)('A' - 10);
        }
        if (digit >= base)
        {
            if (chr >= '0' && chr <= '9')
            {
                bad_num = ErrBadNumDigit;
            }
            else if (chru >= 'A' && chru <= 'Z')
            {
                bad_num = ErrBadNumDigit;
            }
            break;
        }

        pos += 1;
        digits += 1;

        next = rv * base + digit;
        if (rv > pre_overflow || next < rv)
        {
            bad_num = ErrBadNumOverflow;
            break;
        }
        rv = next;
    }

    if (digits == 0)
    {
        bad_num = ErrBadNumNoDigit;
    }

    if (bad_num)
    {
        return (Token){TokBadNumber, start, pos - start, bad_num};
    }
    else
    {
        return (Token){TokNumber, start, pos - start, rv};
    }
}

Token token(char *input, size_t len, size_t pos)
{
    char chr, chru;
    char *ptr = &input[pos];
    while (pos < len && (input[pos] == ' ' || input[pos] == '\t'))
    {
        pos += 1;
    }
    if (pos == len)
    {
        return (Token){TokEOF, pos, 0, 0};
    }
    ptr = &input[pos];
    chr = *ptr;
    if (chr == ',' || chr == '-' || chr == '.' || chr == ':')
    {
        return (Token){(TokenKind)chr, pos, 1, 0};
    }
    if (chr == '\n')
    {
        return (Token){TokNewline, pos, 1, 0};
    }
    if (chr == '\r')
    {
        if (pos + 1 < len && ptr[1] == '\n')
        {
            return (Token){TokNewline, pos, 2, 0};
        }
        return (Token){TokNewline, pos, 1, 0};
    }
    if (chr == ';')
    {
        size_t clen = 1;
        while (pos + clen < len && ptr[clen] != '\n' && ptr[clen] != '\r')
        {
            clen += 1;
        }
        return (Token){TokComment, pos, clen, 0};
    }
    if (chr >= '0' && chr <= '9')
    {
        return token_number(input, len, pos);
    }
    chru = chr & ~0x20;
    if (chr == '_' || (chru >= 'A' && chru <= 'Z'))
    {
        return token_ident(input, len, pos);
    }
    return (Token){TokInvalid, pos, 1, 0};
}

typedef struct Hole_s
{
    size_t location;
    size_t origin;
    char *str;
    size_t len;
    size_t size;
} Hole;
typedef struct HoleVec_s
{
    Hole *buf;
    size_t cap;
    size_t len;
} HoleVec;
typedef struct Label_s
{
    size_t location;
    char *str;
    size_t len;
} Label;
typedef struct LabelVec_s
{
    Label *buf;
    size_t cap;
    size_t len;
} LabelVec;

size_t label_lookup(LabelVec *labels, char *name, size_t len)
{
    size_t nlabels = labels->len;
    Label *buf = labels->buf;
    for (size_t ii = 0; ii < nlabels; ii += 1)
    {
        if (len == buf->len && strncmp(buf->str, name, len) == 0)
        {
            return ii;
        }
        buf += 1;
    }
    return INVALID;
}

int parse_register(char *name, size_t len)
{
    if (name[0] != 'r')
    {
        return 256; // Register name should start with 'r'
    }
    if (len > 4)
    {
        return 256; // Register name too long
    }
    uint16_t rv = 0;
    if (len > 2 && name[1] == '0')
    {
        return 256; // Extra zero suffix
    }
    for (size_t ii = 1; ii < len; ii += 1)
    {
        char chr = name[ii];
        if (!(chr >= '0' && chr <= '9'))
        {
            return 256; // Register name must only contain numbers
        }
        rv = rv * 10 + (chr - '0');
    }
    if (rv > 255)
    {
        return 256; // Register number too large
    }
    return (int)rv;
}

// safety: assumes the buffer has enough place for specified integer size
AsmError push_int_le(char *buf, uint64_t val, size_t size, uint8_t sign)
{
    int valid_uint = val >> (size * 8) == 0;
    int64_t int_shifted = ((int64_t)val) >> (size * 8 - 1);
    int valid_int = int_shifted == 0 || (~int_shifted) == 0;
    // Note: this assumes the format for `sign` is a bitset.
    int validity = valid_int | (valid_uint << 1);
    if ((validity & sign) == 0)
    {
        return ErrImmediateOverflow;
    }
    for (size_t ii = 0; ii < size; ii += 1)
    {
        buf[ii] = val & 0xff;
        val >>= 8;
    }
    return ErrOk;
}

AsmError assemble_instr(
    InstHt ht, char *input, size_t len, Token *tok,
    ByteVec *rv, HoleVec *holes, LabelVec *labels)
{
    const InstDesc *inst;
    const char *type_str;
    size_t nargs;
    size_t size;
    size_t idx = inst_lookup(ht, &input[tok->start], tok->len);
    size_t inst_start = rv->len;
    if (idx == INVALID)
    {
        return ErrInvalidToken;
    }
    inst = &INST[idx];
    type_str = TYPE_STR[inst->type];
    nargs = strlen(type_str);
    size = 1;
    for (size_t ii = 0; ii < nargs; ii += 1)
    {
        char chr = type_str[ii];
        ArgMeta meta = arg_meta(chr);
        if (meta.chr == 0)
        {
            return ErrBadArgumentMeta;
        }
        size += meta.size;
    }
    if (ensure_push(rv, 1, size) != 0)
    {
        return ErrOutOfMemory;
    }
    rv->buf[rv->len] = inst->opcode;
    rv->len += 1;
    for (size_t ii = 0; ii < nargs; ii += 1)
    {
        if (ii > 0)
        {
            *tok = token(input, len, tok->start + tok->len);
            if (tok->kind != TokComma)
            {
                return ErrNeedCommaAfterArgument;
            }
        }
        char chr = type_str[ii];
        ArgMeta meta = arg_meta(chr);
        uint64_t is_negative = 0;
        *tok = token(input, len, tok->start + tok->len);
        if (tok->kind == TokNeg)
        {
            *tok = token(input, len, tok->start + tok->len);
            is_negative = ~(uint64_t)0;
        }
        if (chr == 'R')
        {
            int reg = parse_register(&input[tok->start], tok->len);
            if (reg > 255)
            {
                return ErrBadRegister;
            }
            rv->buf[rv->len] = (char)(reg & 0xff);
            rv->len += 1;
        }
        else
        {
            uint64_t num_to_write;
            if (meta.rel == 1 || meta.size == 8)
            {
                if (tok->kind == TokIdent)
                {
                    size_t idx = label_lookup(labels, &input[tok->start], tok->len);
                    if (idx == INVALID)
                    {
                        if (ensure_push((ByteVec *)holes, 1, sizeof(Hole)) != 0)
                        {
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
                    }
                    else
                    {
                        num_to_write = labels->buf[idx].location;
                        if (meta.size != 8)
                        {
                            num_to_write -= inst_start;
                        }
                    }
                }
                else if (tok->kind == TokNumber)
                {
                    num_to_write = tok->num;
                }
                else
                {
                    return ErrLabelImmediate;
                }
            }
            else if (tok->kind == TokNumber)
            {
                num_to_write = tok->num;
            }
            else
            {
                return ErrNumberImmediate;
            }
            // num_to_write = num_to_write ^ is_negative - is_negative;
            if (is_negative)
            {
                int64_t tmp = -(int64_t)num_to_write;
                if (tmp > 0)
                {
                    return ErrBadNumOverflow;
                }
                num_to_write = (uint64_t)tmp;
            }
            AsmError err = push_int_le(
                &rv->buf[rv->len], num_to_write, meta.size, meta.sign);
            if (err != 0)
            {
                return err;
            }
            rv->len += meta.size;
        }
    }

    return 0;
}

typedef struct EInfo_s
{
    Token token;
    size_t line;
    size_t line_start;
} EInfo;

AsmError assemble(InstHt ht, char *input, size_t len, ByteVec *out, EInfo *einfo)
{
    ByteVec rv = {malloc(MIN_SIZE), MIN_SIZE, 0};
    HoleVec holes = {malloc(MIN_SIZE * sizeof(Hole)), MIN_SIZE, 0};
    LabelVec labels = {malloc(MIN_SIZE * sizeof(Label)), MIN_SIZE, 0};
    size_t line = 0;
    size_t line_start = 0;
    size_t pos = 0;
    // init=0, label=1, instruction=2, comment=3, newline -> 0
    size_t line_state = 0;
    AsmError err = ErrOk;

    while (1)
    {
        Token tok = token(input, len, pos);
        einfo->token = tok;
        pos = tok.start + tok.len;
        if (tok.kind == TokInvalid || tok.kind == TokBadNumber)
        {
            if (tok.num)
            {
                err = (AsmError)tok.num;
            }
            else
            {
                err = ErrInvalidToken;
            }
            break;
        }
        if (tok.kind == TokEOF)
        {
            break;
        }
        if (tok.kind == TokComment)
        {
            line_state = 3;
            continue;
        }
        if (tok.kind == TokNewline)
        {
            line += 1;
            line_start = tok.start + tok.len;
            line_state = 0;
            continue;
        }
        if (tok.kind == TokDot)
        {
            Token next = token(input, len, pos);
            if (next.kind == TokIdent)
            {
                err = ErrDirectiveNotImplemented;
                goto end;
            }
            else
            {
                err = ErrNeedDirectiveAfterDot;
                goto end;
            }
            continue;
        }
        if (tok.kind == TokIdent)
        {
            Token next = token(input, len, pos);
            if (next.kind == TokColon)
            {
                // Label
                pos = next.start + next.len;
                if (line_state >= 1)
                {
                    err = ErrLabelAfterLabel;
                    einfo->token = next;
                    goto end;
                }
                line_state = 1;
                if (ensure_push((ByteVec *)&labels, sizeof(Label), 1) != 0)
                {
                    err = ErrOutOfMemory;
                    goto end;
                }
                size_t idx = label_lookup(&labels, &input[tok.start], tok.len);
                if (idx != INVALID)
                {
                    err = ErrDuplicateLabel;
                    goto end;
                }
                labels.buf[labels.len] = (Label){
                    .location = rv.len,
                    .str = &input[tok.start],
                    .len = tok.len,
                };
                labels.len += 1;
            }
            else
            {
                // Instruction
                if (line_state >= 2)
                {
                    err = ErrTrailingLine;
                    goto end;
                }
                line_state = 2;
                err = assemble_instr(
                    ht, input, len, &tok,
                    &rv, &holes, &labels);
                pos = tok.start + tok.len;
                if (err != 0)
                {
                    goto end;
                }
            }
            continue;
        }
        err = ErrUnexpectedToken;
        goto end;
    }

    for (size_t ii = 0; ii < holes.len; ii += 1)
    {
        Hole *hole = &holes.buf[ii];
        size_t idx = label_lookup(&labels, hole->str, hole->len);
        uint64_t num_to_write = labels.buf[idx].location;
        uint8_t sign = 1;
        if (hole->size != 8)
        {
            sign = 2;
            num_to_write -= hole->origin;
        }
        err = push_int_le(
            &rv.buf[hole->location], num_to_write, hole->size, sign);
        if (err != 0)
        {
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

int main(int argc, char **argv)
{
    int hex_out = 0;
    if (argc >= 2 && strcmp(argv[1], "--hex") == 0)
    {
        hex_out = 1;
    }

    int err = 0;
    InstHt ht = NULL;
    ByteVec input;

    err = slurp(stdin, &input);
    if (err != 0)
    {
        fprintf(stderr, "failed to read the file: %d\n", err);
        goto done;
    }
    ht = build_lookup();
    if (ht == NULL)
    {
        err = ErrOutOfMemory;
        fprintf(stderr, "failed to init hash table: %d\n", err);
        goto done;
    }

    ByteVec out;
    EInfo einfo;
    err = assemble(ht, input.buf, input.len, &out, &einfo);
    if (err != 0)
    {
        size_t column = einfo.token.start - einfo.line_start + 1;
        fprintf(stderr, "failed to assemble, %s, line=%zu, col=%zu token=%.*s\n",
                ERRORS[err], einfo.line, column,
                (int)einfo.token.len, &input.buf[einfo.token.start]);
        goto done;
    }
    if (hex_out)
    {
        hd(out.buf, out.len);
    }
    else
    {
        fwrite(out.buf, 1, out.len, stdout);
    }

done:
    free(ht);
    free(input.buf);
    free(out.buf);
    return err;
}
