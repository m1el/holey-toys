AsmError push_string(char *buf, char *input, size_t len) {
    size_t ndata = 0;
    for (size_t pos = 0; pos < len; pos += 1) {
        char chr = input[pos];
        if (chr == '\\') {
            pos += 1;
            if (pos + 1 >= len) {
                return ErrDanglingEscape;
            }
            chr = input[pos];
            size_t offset = 1;
            switch (chr) {
                case '\\':
                    chr = '\\';
                    break;
                case '"':
                    chr = '"';
                    break;
                case 'r':
                    chr = '\r';
                    break;
                case 'n':
                    chr = '\n';
                    break;
                case '0':
                    chr = '\0';
                    break;
                case 't':
                    chr = '\t';
                    break;
                case 'x':
                    if (pos + 2 >= len) {
                        return ErrDanglingEscape;
                    }
                    char high = get_hex(input[pos + 1]);
                    char low = get_hex(input[pos + 2]);
                    offset = 2;
                    if (high > 15 || low > 15) {
                        return ErrStringBadHex;
                    }
                    chr = high << 4 | low;
                    break;
                default:
                    return ErrBadStringEscape;
            }
            pos += offset;
        }
        buf[ndata] = chr;
        ndata += 1;
    }
    return ErrOk;
}

static AsmError push_data(char *input, size_t len, ByteVec *out, Token *tok,
                          size_t word_size) {
    while (1) {
        *tok = token(input, len, tok->start + tok->len);
        if (tok->kind == TokNumber) {
            if (ensure_push(out, 1, word_size) != 0) {
                return ErrOutOfMemory;
            }
            push_int_le(&out->buf[out->len], tok->num, word_size, 3);
            out->len += word_size;
        } else if (tok->kind == TokString) {
            if (word_size != 1) {
                return ErrStringDataNotByte;
            }
            if (ensure_push(out, 1, tok->num) != 0) {
                return ErrOutOfMemory;
            }

            char *str = &input[tok->start + 1];
            AsmError err = push_string(&out->buf[out->len], str, tok->len - 2);
            if (err != ErrOk) {
                return err;
            }
            out->len += tok->num;
        } else {
            return ErrNeedsDataLiteral;
        }
        *tok = token(input, len, tok->start + tok->len);
        if (tok->kind == TokNewline || tok->kind == TokEOF) {
            return ErrOk;
        }
        if (tok->kind == TokComma) {
            continue;
        }
        return ErrNeedCommaOrNewline;
    }
}

AsmError assemble_directive(char *input, size_t len, ByteVec *out, Token *tok) {
    if (tok->len < 2) {
        return ErrInvalidDirective;
    }
    size_t pos = tok->start;
    char byte0 = input[pos];
    char byte1 = input[pos + 1];
    if (tok->len == 0 && byte0 == 'd') {
        size_t word_size;
        switch (byte1) {
            case 'b':
                word_size = 1;
                break;
            case 'w':
                word_size = 2;
                break;
            case 'd':
                word_size = 4;
                break;
            case 'q':
                word_size = 8;
                break;
            default:
                return ErrInvalidDirective;
        }
        return push_data(input, len, out, tok, word_size);
    }
    if (tok->len == 5 && strncmp("align", &input[pos], 5) == 0) {
        *tok = token(input, len, tok->start + tok->len);
        if (tok->kind != TokNumber) {
            return ErrAlignNeedsNumber;
        }
        size_t mask = tok->num - 1;
        if ((tok->num & mask) != 0) {
            return ErrAlignNeedsPow2;
        }
        if ((~(size_t)0) - mask < out->len) {
            return ErrOutOfMemory;
        }
        size_t aligned = (out->len + mask) & ~mask;
        if (ensure_push(out, 1, aligned - out->len) != 0) {
            return ErrOutOfMemory;
        }
        // TODO: zero-fill?
        out->len = aligned;
    }
    return ErrOk;
}
