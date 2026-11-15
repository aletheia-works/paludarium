#!/usr/bin/env python3
"""Writes x87_transcendental.h: inputs for the x87 transcendental instructions
and their correctly rounded results, which the x87-transcendental case compares
a CPU with and the CPU crate's unit tests compare the emulator with.

After changing what it chooses, `mise run x87:table` writes the header again
(with mpmath, which uv fetches); `lint:all` checks that the two agree.

The results follow what Intel's and AMD's CPUs compute, rounded once: fsin,
fcos, fsincos and fptan take away multiples of pi/2 as pi/2 cut to 66 bits,
f2xm1 is 2^x - 1, fpatan is atan2(st1, st0), fyl2x is st1 * log2(st0) and
fyl2xp1 is st1 * log2(st0 + 1). Every result notes PE, a tiny one UE, and a
denormal operand DE; C1 says whether the size went up.
"""

from mpmath import atan2, cos, floor, ldexp, log, mp, mpf, sin

mp.prec = 600

BIAS = 16383
# pi/2 cut to 66 bits, as the CPUs reduce with it.
HALF_PI = ldexp(mpf(0x3243F6A8885A308D3), -65)


def value(encoding):
    sign, exponent, mantissa = encoding >> 79, encoding >> 64 & 0x7FFF, encoding & (2**64 - 1)
    v = ldexp(mpf(mantissa), max(exponent, 1) - BIAS - 63)
    return -v if sign else v


def round80(x, mode):
    """x in the 80-bit format, rounded as the control word's mode says, and
    whether its size went up."""
    negative = x < 0
    size = -x if negative else x
    exponent = int(floor(log(size, 2)))
    if ldexp(mpf(1), exponent) > size:
        exponent -= 1
    elif ldexp(mpf(1), exponent + 1) <= size:
        exponent += 1
    unit = max(exponent, 1 - BIAS) - 63
    scaled = ldexp(size, -unit)
    whole = int(floor(scaled))
    rest = scaled - whole
    away = {
        0: rest > 0.5 or (rest == 0.5 and whole & 1),
        1: negative and rest > 0,
        2: not negative and rest > 0,
        3: False,
    }[mode]
    whole += away
    if whole == 2**64:
        whole, unit = 2**63, unit + 1
    field = unit + 63 + BIAS if whole >> 63 else 0
    if field >= 0x7FFF:
        if mode == 0 or mode == 1 + (not negative):
            return (negative << 79) | 0x7FFF8000000000000000, True
        return (negative << 79) | 0x7FFEFFFFFFFFFFFFFFFF, False
    return (negative << 79) | (field << 64) | whole, away


def trigonometric(x):
    n = int(floor(x / HALF_PI + mpf(1) / 2))
    r = x - n * HALF_PI
    s, c = sin(r), cos(r)
    return [(s, c), (c, -s), (-s, -c), (-c, s)][n % 4]


def results(op, a, b):
    if op in ("fsin", "fcos", "fsincos", "fptan"):
        s, c = trigonometric(value(a))
        return {"fsin": [s], "fcos": [c], "fsincos": [s, c], "fptan": [s / c, mpf(1)]}[op]
    if op == "f2xm1":
        return [mp.expm1(value(a) * log(2))]
    y, x = value(a), value(b)
    if op == "fpatan":
        return [atan2(y, x)]
    if op == "fyl2x":
        return [y * log(x, 2)]
    return [y * mp.log1p(x) / log(2)]


def denormal(encoding):
    return encoding >> 64 & 0x7FFF == 0 and encoding & (2**64 - 1) != 0


def entry(op, mode, a, b=0):
    values, flags, up = [], 0x20, False
    # Enough bits that even the second term of a series on a tiny value
    # reaches the rounding.
    small = max(BIAS - (e >> 64 & 0x7FFF) for e in (a, b) if e)
    mp.prec = 600 + 3 * max(small, 0)
    for k, exact in enumerate(results(op, a, b)):
        rounded, away = round80(exact, mode)
        values.append(rounded)
        if rounded >> 64 & 0x7FFF == 0:
            flags |= 0x10
        if exact != value(rounded) and abs(exact) > value(0x7FFEFFFFFFFFFFFFFFFF):
            flags |= 0x08
        if k == 0:
            up = away
    if denormal(a) or (op in ("fpatan", "fyl2x", "fyl2xp1") and denormal(b)):
        flags |= 0x02
    if up:
        flags |= 0x200
    return op, mode, a, b, values, flags


state = 0x123456789ABCDEF


def random():
    global state
    state ^= state << 13 & (2**64 - 1)
    state ^= state >> 7
    state ^= state << 17 & (2**64 - 1)
    return state


def number(low, high, signed=True):
    """A value whose power of two is from low to high, with long runs of
    ones and zeros now and then."""
    pick = random()
    power = low + pick % (high - low + 1)
    mantissa = random() | 1 << 63
    if pick >> 40 & 1:
        run = pick >> 41 & 63
        mantissa = (
            mantissa | ((2**64 - 1) >> run)
            if pick >> 47 & 1
            else (mantissa & ~((2**64 - 1) >> run)) | 1 << 63
        )
    sign = signed and pick >> 50 & 1
    return (sign << 79) | ((BIAS + power) << 64) | mantissa


def near_quarters():
    """Near a multiple of pi/4, where what is taken away matters."""
    k = random() % (1 << (6 if random() & 1 else 30))
    x = k * HALF_PI / 2
    if x == 0:
        return number(-3, -1)
    encoding, _ = round80(x, 0)
    encoding += random() % 9 - 4
    return encoding | (random() & 1) << 79


# Finite values that are not zero, which the case also takes as its special
# ones: they are compared with each other for the instructions of two.
SPECIAL = [
    0x3FFF8000000000000000,
    0xBFFF8000000000000000,
    0x40008000000000000000,
    0x3FFE8000000000000000,
    0x00000000000000000001,
    0x80007FFFFFFFFFFFFFFF,
    0x00018000000000000000,
    0x3FFFB504F333F9DE6484,
    0x3FFD95F619980C4336F7,
    0xBFFD95F619980C4336F7,
    0x4000C90FDAA22168C235,
    0x403D8000000000000000,
    0x7FFEFFFFFFFFFFFFFFFF,
    0x3FBF8000000000000000,
]


def entries():
    out = []
    one = ["fsin", "fcos", "fsincos", "fptan"]
    for op in one:
        for n in range(120):
            if n < 70:
                a = number(-64, 3)
            elif n < 95:
                a = number(3, 62)
            else:
                a = near_quarters()
            out.append(entry(op, n % 4, a))
        # Tiny values, in the nearest rounding only: Intel's CPUs give the
        # value itself whichever way they round.
        for _ in range(8):
            out.append(entry(op, 0, number(-16000, -64)))
    for op in [*one, "f2xm1"]:
        for a in SPECIAL:
            if abs(value(a)) > (1 if op == "f2xm1" else 2**63):
                continue
            tiny = abs(value(a)) < ldexp(mpf(1), -64)
            for mode in range(1 if tiny else 4):
                out.append(entry(op, mode, a))
    for n in range(120):
        a = number(-70, -1) if n < 105 else number(-16000, -70)
        mode = n % 4 if n < 105 else 0
        out.append(entry("f2xm1", mode, a))
    for a in (0x3FFF8000000000000000, 0xBFFF8000000000000000):
        out.append(entry("f2xm1", 0, a))
    for n in range(120):
        y = number(-40, 40)
        if n < 45:
            x = number(-1, 0, False)
        elif n < 60:
            x = (BIAS << 64) | 1 << 63 | random() >> (10 + random() % 50)
        elif n < 75:
            x = ((BIAS - 1) << 64) | ((2**64 - 1) ^ random() >> (10 + random() % 50))
        else:
            x = number(-16000, 16000, False)
        out.append(entry("fyl2x", n % 4, y, x))
    for n in range(120):
        y = number(-40, 40)
        if n < 90:
            x = number(-70, -2)
        elif n < 105:
            x = number(-1, 12, False)
        else:
            # Between -1 and the range the manuals define, where the CPUs
            # still compute it.
            x = (1 << 79) | ((BIAS - 2 + random() % 2) << 64) | random() | 1 << 63
        out.append(entry("fyl2xp1", n % 4, y, x))
    for n in range(120):
        y, x = number(-70, 70), number(-70, 70)
        if n < 45:
            x = (y ^ (random() & 1) << 79) + ((random() % 5 - 2) << 64) ^ random() >> (
                random() % 63 + 1
            ) | 1 << 63
        out.append(entry("fpatan", n % 4, y, x))
    for op in ("fpatan", "fyl2x", "fyl2xp1"):
        for y in SPECIAL:
            for x in SPECIAL:
                if op == "fyl2x" and (x >> 79 or x == 0x3FFF8000000000000000):
                    continue
                if op == "fyl2xp1" and value(x) <= -1:
                    continue
                out.append(entry(op, 0, y, x))
    return out


def main():
    lines = [
        "/* Generated by x87_transcendental.py, which says what these are: the",
        "   instruction, the control word's rounding, st(1) and st(0) (or st(0)",
        "   alone), the results (st(0) and what is pushed onto it), and the status",
        "   word's exceptions and C1. */",
        "static const struct x87_expected {",
        "    const char *op;",
        "    int mode;",
        "    const char *a, *b, *first, *second;",
        "    uint16_t flags;",
        "} x87_expected[] = {",
    ]

    def v(e):
        return f'"{e:020x}"' if e is not None else '""'

    for op, mode, a, b, values, flags in entries():
        second = values[1] if len(values) > 1 else None
        b = b if op in ("fpatan", "fyl2x", "fyl2xp1") else None
        fields = ", ".join(
            [f'"{op}"', str(mode), v(a), v(b), v(values[0]), v(second), f"0x{flags:03x}"]
        )
        lines.append(f"    {{{fields}}},")
    lines.append("};")
    print("\n".join(lines))


main()
