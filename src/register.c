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