// Instruction Hash table, for faster lookups
typedef struct InstHtNode_s
{
    uint8_t index1;
    uint8_t index2;
} InstHtNode;
typedef InstHtNode *InstHt;

uint32_t inst_hash(const char *s, size_t len)
{
    uint32_t hash = 0;
    uint32_t mul = 75;
    for (size_t ii = 0; ii < len; ii += 1)
    {
        hash ^= s[ii] * mul;
        hash *= mul;
    }
    return hash;
}

InstHt build_lookup(void)
{
    const size_t size = 256;
    InstHt table = (InstHt)malloc(size * sizeof(InstHtNode));
    if (table == NULL)
    {
        return table;
    }
    for (size_t ii = 0; ii < size; ii += 1)
    {
        table[ii] = (InstHtNode){0xff, 0xff};
    }
    for (size_t ii = 0; ii < INST_CNT; ii += 1)
    {
        const char *mnemonic = INST[ii].mnemonic;
        uint32_t hash = inst_hash(mnemonic, strlen(mnemonic));
        InstHtNode *node = &table[hash & 0xff];
        if (node->index1 == 0xff)
        {
            node->index1 = ii;
        }
        else if (node->index2 == 0xff)
        {
            node->index2 = ii;
        }
        else
        {
            fprintf(stderr, "more than 1 collision in hash table\n");
            exit(1);
        }
    }
    return table;
}

size_t inst_lookup(InstHt ht, const char *s, size_t len)
{
    uint32_t hash = inst_hash(s, len);
    uint8_t *node = (uint8_t *)&ht[(size_t)(hash & 0xff)];
    for (size_t ii = 0; ii < 2; ii += 1)
    {
        size_t idx = (size_t)node[ii];
        if (idx == 0xff)
        {
            break;
        }
        const char *mnemonic = INST[idx].mnemonic;
        if (strncmp(s, mnemonic, len) == 0 && mnemonic[len] == 0)
        {
            return idx;
        }
    }
    return INVALID;
}
