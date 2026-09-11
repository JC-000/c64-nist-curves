#!/usr/bin/env python3
"""Gate: all device traffic in tools/ enters at the harness's own altitude.

Why this exists
---------------
The harness is meant to be the single point where traffic to an Ultimate
device can be filtered — capability-aware PUT/POST selection, chunking,
``/Temp`` hygiene, and whatever budget or refusal lands next.  That only
works if every tool enters at the managed layer and lets the harness
decide.  A fix added there covers every tool at once; a fix added at a
call site has to be repeated everywhere and rots when the next call site
appears.

So the rule is about **altitude, not chunking**:

* ``transport.write_memory`` is the sanctioned entry point.  It already
  consults the device-capability table to pick ``PUT ?data=`` over the
  leaking ``POST /v1/machine:writemem``.  Use it directly.
* Do **not** pre-chunk at the call site.  It looks like hygiene and is
  really a policy decision moved to the wrong layer: the available
  helper, ``memory.write_bytes``, chunks at 84 B because that is where
  VICE's text monitor truncates (``memory.py:14-16``) — a VICE constant,
  not a device one.  It happens to fall under the Ultimate's 128 B
  ceiling, and a coincidence is not a contract.  Pre-chunking also costs
  a round trip per chunk and has to be unpicked once the harness lands
  device-aware chunking in ``write_memory``.
* Do **not** reach below the transport — no ``client.write_mem``, no
  ``_post_binary`` / ``_request``, no raw HTTP or sockets.  Those skip
  the policy layer entirely and are invisible to any harness-side fix.

Known gap this gate does not close: upload *volume*.  ``client.run_prg``
is unconditionally a POST, and while the harness now spends `/Temp`
budget per body-carrying request and runs hygiene when the device's
capability arms it, how many uploads a run issues is still operator
choice (``--speeds``).  That is a sizing decision, not an altitude one.

Legs
----
1. altitude  -- no call reaching below the harness's managed transport
2. bypass    -- no raw HTTP/socket client reaching a device around the harness
3. harness   -- no sys.path manipulation that could shadow the installed harness

Each leg carries a positive control so a green result cannot mean "the
detector found nothing because it examines nothing" (see the seven
green-but-empty shapes in .claude/agents/adversarial-reviewer.md lane 4).

Exit 0 on pass, 1 on any failure.  No device, no VICE, no network.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent

#: This gate polices the repo's own tools.  The checker itself is excluded
#: (its docstring and patterns quote the very strings it looks for).
EXCLUDE = {"check_harness_routing.py"}

#: Calls that reach BELOW the harness's managed transport.
#:
#: ``transport.write_memory`` is the sanctioned entry point and is NOT
#: flagged: it is where the harness applies its device-capability policy
#: (PUT vs POST) and where chunking and hygiene belong.  Pre-chunking at a
#: call site would bake a chunk size into this repo — and the only helper
#: that offers one, ``memory.write_bytes``, chunks at 84 B for a VICE
#: text-monitor reason (``memory.py:14-16``), not for a device reason.  A
#: number that lands under the Ultimate's 128 B ceiling by coincidence is
#: not a policy, it is a constant we would own and have to re-fix when the
#: harness lands device-aware chunking.
#:
#: What IS flagged is the low-level client method, which skips the
#: transport's policy layer entirely, and the private request helpers.
RE_RAW_WRITE = re.compile(r"\.write_mem\s*\(|\._post_binary\s*\(|\._request\s*\(")

#: Raw network clients that would route around the harness entirely.
RE_RAW_HTTP = re.compile(
    r"\b(?:import\s+requests|from\s+requests\b"
    r"|urllib\.request\b|http\.client\b"
    r"|socket\.socket\s*\(\s*socket\.AF_INET\s*,\s*socket\.SOCK_STREAM)"
)

#: A sys.path insert naming an absolute path outside this repo can shadow
#: the installed harness with an arbitrary (possibly pre-fix) checkout —
#: and with it an arbitrary capability table, which is what decides PUT vs
#: POST.  The real in-tree instance bound the path to a NAME first
#: (``_HARNESS_SRC = "/home/..."`` then ``sys.path.insert(0, _HARNESS_SRC)``),
#: so matching only the literal-argument form made this leg vacuous — it
#: found nothing on the very shim it exists to catch.  Match the absolute
#: path literal itself, wherever it is bound.
#
#: Enumerating platform root directories was the second miss: the list
#: (home|usr|opt|...) omitted ``/Users``, which is the platform this repo
#: actually lives on, while ``/private`` reddened any tool holding a
#: scratchpad path — wrong in both directions at once.  Match on what the
#: shim IS instead of where it points: (a) any absolute path literal
#: naming a harness checkout or an install root, wherever it is bound, and
#: (b) any sys.path mutation carrying an absolute literal.
#: Third refinement: requiring a leading ``/`` on the name alternative
#: missed the ``os.path.join(HOME, "c64-test-harness", "src")`` form —
#: the natural way to write a *portable* version of the deleted shim, and
#: one that defeated both alternatives at once (the segment literal has no
#: slash, and the sys.path alternative cannot see past the inner call's
#: paren).  Match the harness/install name in any string literal.
#: Dropping the leading slash outright then matched ``c64_test_harness``
#: inside docstrings and f-strings — including this repo's own provenance
#: printer.  The separating fact: the *module* is ``c64_test_harness``
#: (underscores) and appears legitimately in imports and prose, while the
#: *directory* a shim points at is ``c64-test-harness`` (hyphens).  So the
#: hyphenated form is a path segment wherever it appears; the underscored
#: form counts only inside something already shaped like a path.
RE_PATH_SHIM = re.compile(
    r"[\"'][^\"']*c64-test-harness"
    r"|[\"'][^\"']*/[^\"']*(?:c64_test_harness|site-packages|dist-packages)"
    r"|sys\.path\.(?:insert|append)\s*\([^)]*[\"']/"
)

#: Positive controls: text the detectors MUST flag.  If a detector stops
#: matching these, it has been broken by an edit and the leg's silence
#: means nothing.  This is what keeps an empty population honest.
CONTROLS = [
    (RE_RAW_WRITE, "self._client.write_mem(addr, data)"),
    (RE_RAW_WRITE, "client._post_binary('/v1/runners:run_prg', data)"),
    (RE_RAW_HTTP, "import requests"),
    (RE_RAW_HTTP, "urllib.request.urlopen(url)"),
    (RE_PATH_SHIM, 'sys.path.insert(0, "/home/someone/c64-test-harness/src")'),
    # The form actually found in-tree: bound to a name, inserted by name.
    (RE_PATH_SHIM, '_HARNESS_SRC = "/home/someone/c64-test-harness/src"'),
    # The same shim on THIS repo's own platform -- the form the first two
    # versions of this detector could not see.
    (RE_PATH_SHIM, '_HARNESS_SRC = "/Users/someone/c64-test-harness/src"'),
    (RE_PATH_SHIM, 'sys.path.append("/opt/homebrew/lib/python3.13/site-packages")'),
    (RE_PATH_SHIM, 'sys.path.insert(1, "/home/x/src")'),
    # The portable form: path split across os.path.join segments, no
    # leading slash on any of them.
    (RE_PATH_SHIM,
     'sys.path.insert(0, os.path.join(HOME, "c64-test-harness", "src"))'),
    (RE_PATH_SHIM, 'os.environ["PYTHONPATH"] = "/Users/x/c64-test-harness/src"'),
]

#: Negative controls: text the detectors MUST NOT flag, so a leg cannot
#: pass by matching everything.
ANTI_CONTROLS = [
    # The managed entry point. Flagging it would push chunking policy back
    # into our call sites, which is the thing this gate exists to prevent.
    (RE_RAW_WRITE, "transport.write_memory(addr, payload)"),
    (RE_RAW_WRITE, "t.write_memory(l['ecdsa_inputs_384'], payload)"),
    (RE_RAW_HTTP, "from c64_test_harness.memory import write_bytes"),
    (RE_PATH_SHIM, "sys.path.insert(0, PROJECT_ROOT)"),
    # A scratchpad path is not harness shadowing; the previous detector
    # flagged it and that was a false positive, not a finding.
    (RE_PATH_SHIM, 'SCRATCH = "/private/tmp/foo"'),
    # The module name in prose or an import is not a path shim. Matching
    # it flagged this repo's own provenance printer.
    (RE_PATH_SHIM, '"""Print which c64_test_harness was loaded."""'),
    (RE_PATH_SHIM, 'print(f"  harness: {c64_test_harness.__file__}")'),
]


def _sources() -> list[Path]:
    return sorted(
        p for p in TOOLS.glob("*.py") if p.name not in EXCLUDE
    )


def _scan(paths: list[Path], pattern: re.Pattern[str]) -> list[str]:
    hits: list[str] = []
    for path in paths:
        for n, line in enumerate(path.read_text().splitlines(), 1):
            code = line.split("#", 1)[0]
            if pattern.search(code):
                rel = path.relative_to(REPO)
                hits.append(f"{rel}:{n}: {line.strip()}")
    return hits


def main() -> int:
    failures: list[str] = []
    sources = _sources()

    # --- Leg 0: the detectors themselves --------------------------------
    for pattern, sample in CONTROLS:
        if not pattern.search(sample):
            failures.append(
                f"detector self-test FAILED: {pattern.pattern!r} no longer "
                f"matches its positive control {sample!r} — every leg using "
                f"it is now vacuous"
            )
    for pattern, sample in ANTI_CONTROLS:
        if pattern.search(sample):
            failures.append(
                f"detector self-test FAILED: {pattern.pattern!r} matches its "
                f"NEGATIVE control {sample!r} — the leg would flag sanctioned "
                f"code"
            )
    if not sources:
        failures.append(
            "population is EMPTY: no tools/*.py scanned — a pass here would "
            "mean nothing"
        )

    # --- Leg 1: writes route through the harness ------------------------
    raw_writes = _scan(sources, RE_RAW_WRITE)
    for hit in raw_writes:
        failures.append(
            f"[routing] direct transport/client write bypasses the harness "
            f"chunking layer: {hit}"
        )

    # --- Leg 2: no raw network client around the harness ----------------
    for hit in _scan(sources, RE_RAW_HTTP):
        failures.append(f"[bypass] raw network client in a tool: {hit}")

    # --- Leg 3: one harness, resolved the same way everywhere -----------
    for hit in _scan(sources, RE_PATH_SHIM):
        failures.append(
            f"[harness] absolute sys.path shim can shadow the installed "
            f"harness (and its capability table): {hit}"
        )

    print(f"scanned {len(sources)} tool sources under {TOOLS.relative_to(REPO)}/")
    print(f"  leg 1 altitude: {len(raw_writes)} sub-harness call(s)")
    print(f"  detectors     : {len(CONTROLS)} positive + "
          f"{len(ANTI_CONTROLS)} negative controls")

    if failures:
        print(f"\nFAIL — {len(failures)} finding(s):\n")
        for f in failures:
            print(f"  {f}")
        print(
            "\nFix: enter at the harness layer -- transport.write_memory()\n"
            "for writes, client.run_prg() for uploads -- and let the\n"
            "harness apply device policy. Do not pre-chunk at the call\n"
            "site and do not reach below the transport.\n"
        )
        return 1

    print("\nPASS — all device traffic in tools/ enters at the harness layer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
