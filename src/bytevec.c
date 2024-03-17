const size_t INVALID = ~(size_t)0;

typedef struct ByteVec_s {
    char *buf;
    size_t cap;
    size_t len;
} ByteVec;

static AsmError ensure_push(ByteVec *vec, size_t el_size, size_t extra) {
    if (vec->len + extra < vec->len) {
        return ErrOutOfMemory;
    }
    while (vec->len + extra > vec->cap) {
        if ((~(size_t)0) / 2 < vec->cap) {
            return ErrOutOfMemory;
        }
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
