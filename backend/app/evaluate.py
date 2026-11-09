"""M2/M3 static scanner evaluation over a curated synthetic corpus.

M2  (O-01): >80% detection on the curated case corpus.
M3  (O-03): false-positive reduction on Python negative probes; TP retention reported.
NFR-01: static scan latency. AI model quality/latency is measured separately.

Usage: python app/evaluate.py
Writes EVAL-REPORT.md + eval-results.json in backend/.
"""
from __future__ import annotations
import asyncio
import json
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.eval_corpus import CASES
from app.scanner import python_scanner as py_scanner
from app.scanner import js_scanner


def run_scan(case: dict, validate: bool = True) -> list[dict]:
    if case["language"] == "python":
        if validate:
            return py_scanner.scan(case["code"], case["id"] + ".py")
        return py_scanner.scan(case["code"], case["id"] + ".py", validate=False)
    return js_scanner.scan(case["code"], case["id"] + ".js")


def main() -> None:
    rows: list[dict] = []
    lat: list[float] = []
    # warm up persistent JS worker so cold-start spawn isn't counted
    try:
        js_scanner.scan("var a = 1;", "warmup.js")
    except Exception:
        pass
    for case in CASES:
        t0 = time.perf_counter()
        findings = run_scan(case, validate=True)
        dt = (time.perf_counter() - t0) * 1000.0
        lat.append(dt)
        got = [f["rule_id"] for f in findings]
        exp = case.get("expect")
        neg = exp is None or case.get("negative", False)
        if neg:
            passed = exp not in got if exp else len(got) == 0
        else:
            passed = exp in got
        rows.append({"id": case["id"], "lang": case["language"], "expect": exp,
                     "got": got, "pass": passed, "ms": round(dt, 2)})

    tp_cases = [r for r, c in zip(rows, CASES) if c.get("expect") and not c.get("negative")]
    fp_cases = [r for r, c in zip(rows, CASES) if not c.get("expect") or c.get("negative")]
    m2_hits = sum(1 for r in tp_cases if r["pass"])
    m2_rate = m2_hits / max(1, len(tp_cases))

    # M3: raw vs validated on FP probes + TP retention
    raw_fp = 0
    val_fp = 0
    for case in [c for c in CASES if c["language"] == "python" and (not c.get("expect"))]:
        raw = py_scanner.scan(case["code"], "raw.py", validate=False)
        val = py_scanner.scan(case["code"], "val.py", validate=True)
        raw_fp += len(raw)
        val_fp += len(val)
    fp_reduction = (raw_fp - val_fp) / raw_fp if raw_fp else 0.0
    tp_raw = sum(1 for r, c in zip(rows, CASES)
                 if c["language"] == "python" and c.get("expect")
                 and c["expect"] in [f["rule_id"] for f in py_scanner.scan(c["code"], "r.py", validate=False)])
    tp_val = sum(1 for r in rows if r["pass"] and r["lang"] == "python"
                 and r["expect"] and not [c for c in CASES if c["id"] == r["id"]][0].get("negative"))

    lat_sorted = sorted(lat)
    p50 = lat_sorted[len(lat_sorted) // 2]
    p95 = lat_sorted[int(len(lat_sorted) * 0.95) - 1] if len(lat_sorted) > 1 else lat_sorted[0]

    report = {
        "cases": len(CASES),
        "m2_detection_rate": round(m2_rate, 3),
        "m2_hits": f"{m2_hits}/{len(tp_cases)}",
        "m2_pass": m2_rate > 0.8,
        "m3_raw_fp": raw_fp,
        "m3_val_fp": val_fp,
        "m3_fp_reduction": round(fp_reduction, 3),
        "m3_tp_raw": tp_raw,
        "m3_tp_val": tp_val,
        "m3_pass": fp_reduction > 0.5,
        "nfr01_scan_p50_ms": round(p50, 2),
        "nfr01_scan_p95_ms": round(p95, 2),
        "nfr01_scan_max_ms": round(max(lat), 2),
        "nfr01_under_100ms": max(lat) < 100,
        "rows": rows,
    }
    out_json = BACKEND / "eval-results.json"
    out_json.write_text(json.dumps(report, indent=2))
    md = BACKEND / "EVAL-REPORT.md"
    md.write_text(
        "# CodeShield AI - Evaluation Report (synthetic scanner corpus)\n\n"
        "Results measure only these curated examples and do not establish real-world detection recall.\n"
        f"- Corpus: {len(CASES)} cases ({len(tp_cases)} TP, {len(fp_cases)} negatives)\n"
        f"- M2 detection: **{m2_hits}/{len(tp_cases)} = {m2_rate:.1%}** {'PASS (>80%)' if report['m2_pass'] else 'FAIL'}\n"
        f"- M3 Python negative-probe reduction: raw={raw_fp} validated={val_fp} "
        f"reduction=**{fp_reduction:.1%}** {'PASS (>50%)' if report['m3_pass'] else 'FAIL'}; "
        f"TP retained raw={tp_raw} validated={tp_val}\n"
        f"- NFR-01 static latency: p50={p50:.1f}ms p95={p95:.1f}ms max={max(lat):.1f}ms "
        f"{'PASS (<100ms)' if report['nfr01_under_100ms'] else 'CHECK'}\n\n"
        "## Per-case\n\n| id | lang | expect | got | pass | ms |\n|---|---|---|---|---|---|\n"
        + "".join(f"| {r['id']} | {r['lang']} | {r['expect']} | {','.join(r['got'])} | "
                  f"{'PASS' if r['pass'] else 'FAIL'} | {r['ms']} |\n" for r in rows)
    )
    print(md.read_text())
    print(f"\nwrote {out_json} and {md}")


if __name__ == "__main__":
    main()

