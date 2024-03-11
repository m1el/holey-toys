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
        int good = chr == '_' || (chr >= '0' && chr <= '9') ||
                   (chru >= 'A' && chru <= 'Z');
        if (!good) {
            break;
        }
        pos += 1;
    }
    return (Token){TokIdent, start, pos - start, 0};
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
        if (chr == '_') {
            pos += 1;
            continue;
        }
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
        return (Token){TokBadNumber, start, pos - start, bad_num};
    } else {
        return (Token){TokNumber, start, pos - start, rv};
    }
}

Token token(char *input, size_t len, size_t pos) {
    char chr, chru;
    char *ptr = &input[pos];
    while (pos < len && (input[pos] == ' ' || input[pos] == '\t')) {
        pos += 1;
    }
    if (pos == len) {
        return (Token){TokEOF, pos, 0, 0};
    }
    ptr = &input[pos];
    chr = *ptr;
    if (chr == ',' || chr == '-' || chr == '.' || chr == ':') {
        return (Token){(TokenKind)chr, pos, 1, 0};
    }
    if (chr == '\n') {
        return (Token){TokNewline, pos, 1, 0};
    }
    if (chr == '\r') {
        if (pos + 1 < len && ptr[1] == '\n') {
            return (Token){TokNewline, pos, 2, 0};
        }
        return (Token){TokNewline, pos, 1, 0};
    }
    if (chr == ';') {
        size_t clen = 1;
        while (pos + clen < len && ptr[clen] != '\n' && ptr[clen] != '\r') {
            clen += 1;
        }
        return (Token){TokComment, pos, clen, 0};
    }
    if (chr >= '0' && chr <= '9') {
        return token_number(input, len, pos);
    }
    chru = chr & ~0x20;
    if (chr == '_' || (chru >= 'A' && chru <= 'Z')) {
        return token_ident(input, len, pos);
    }
    return (Token){TokInvalid, pos, 1, 0};
}
