
static bool check_valid_int(uint64_t val, size_t size, uint8_t sign) {
    // All 64-bit values are considered valid.
    if (size == 8) {
        return true;
    }
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
    return (validity & sign) != 0;
}

// safety: assumes the buffer has enough place for specified integer size.
// `sign` is a bitset, where bit `1` indicates that value accepts a signed int,
// and bit `2` indicates that value accepts an unsigned int.
static AsmError push_int_le(char *buf, uint64_t val, size_t size,
                            uint8_t sign) {
    if (!check_valid_int(val, size, sign)) {
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
