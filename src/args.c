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
