# CodeShield AI - Evaluation Report (synthetic scanner corpus)

Results measure only these curated examples and do not establish real-world detection recall.
- Corpus: 37 cases (25 TP, 12 negatives)
- M2 detection: **25/25 = 100.0%** PASS (>80%)
- M3 Python negative-probe reduction: raw=3 validated=0 reduction=**100.0%** PASS (>50%); TP retained raw=15 validated=15
- NFR-01 static latency: p50=0.4ms p95=2.4ms max=4.4ms PASS (<100ms)

## Per-case

| id | lang | expect | got | pass | ms |
|---|---|---|---|---|---|
| PY-TP-01 | python | PY-SQLI-001 | PY-SQLI-001 | PASS | 4.44 |
| PY-TP-02 | python | PY-SQLI-001 | PY-SQLI-001 | PASS | 0.23 |
| PY-TP-03 | python | PY-CMD-001 | PY-CMD-001 | PASS | 0.18 |
| PY-TP-04 | python | PY-SECRETS-001 | PY-SECRETS-001 | PASS | 0.07 |
| PY-TP-05 | python | PY-PATH-001 | PY-PATH-001 | PASS | 0.22 |
| PY-TP-06 | python | PY-SSRF-001 | PY-SSRF-001 | PASS | 0.19 |
| PY-TP-07 | python | PY-SERIAL-001 | PY-SERIAL-001 | PASS | 0.11 |
| PY-TP-08 | python | PY-CODE-EXEC-001 | PY-CODE-EXEC-001 | PASS | 0.06 |
| PY-TP-09 | python | PY-CODE-EXEC-002 | PY-CODE-EXEC-002 | PASS | 0.07 |
| PY-TP-10 | python | PY-CRYPTO-001 | PY-CRYPTO-001 | PASS | 0.09 |
| PY-TP-11 | python | PY-CRYPTO-002 | PY-CRYPTO-002 | PASS | 0.09 |
| PY-TP-12 | python | PY-CONFIG-001 | PY-CONFIG-001 | PASS | 0.07 |
| PY-TP-13 | python | PY-SSRF-001 | PY-SSRF-001 | PASS | 0.18 |
| PY-TP-14 | python | PY-PATH-001 | PY-PATH-001 | PASS | 0.36 |
| PY-TP-15 | python | PY-PASSWORD-HASH-001 | PY-PASSWORD-HASH-001 | PASS | 0.2 |
| PY-FP-01 | python | None |  | PASS | 0.06 |
| PY-FP-02 | python | None |  | PASS | 0.06 |
| PY-FP-03 | python | None |  | PASS | 0.08 |
| PY-FP-04 | python | None |  | PASS | 0.15 |
| PY-FP-05 | python | None |  | PASS | 0.07 |
| JS-TP-01 | javascript | JS-CODE-EXEC-001 | JS-CODE-EXEC-001 | PASS | 4.35 |
| JS-TP-02 | javascript | JS-CODE-EXEC-002 | JS-CODE-EXEC-002 | PASS | 2.09 |
| JS-TP-03 | javascript | JS-SQLI-001 | JS-SQLI-001 | PASS | 2.43 |
| JS-TP-04 | javascript | JS-XSS-001 | JS-XSS-001 | PASS | 2.17 |
| JS-TP-05 | javascript | JS-XSS-001 | JS-XSS-001 | PASS | 1.72 |
| JS-TP-06 | javascript | JS-RANDOM-001 | JS-RANDOM-001 | PASS | 1.22 |
| JS-TP-07 | javascript | JS-SECRETS-001 | JS-SECRETS-001 | PASS | 1.16 |
| JS-TP-08 | javascript | JS-CONFIG-001 | JS-CONFIG-001 | PASS | 1.07 |
| JS-TP-09 | javascript | JS-JWT-001 | JS-JWT-001 | PASS | 1.15 |
| JS-TP-10 | javascript | JS-SQLI-001 | JS-SQLI-001 | PASS | 1.4 |
| JS-FP-01 | javascript | None |  | PASS | 1.45 |
| JS-FP-02 | javascript | None |  | PASS | 1.28 |
| JS-FP-03 | javascript | JS-CRYPTO-001 |  | PASS | 1.21 |
| JS-FP-04 | javascript | None |  | PASS | 1.33 |
| PY-FP-06 | python | None |  | PASS | 0.61 |
| PY-FP-07 | python | None |  | PASS | 0.45 |
| JS-FP-05 | javascript | None |  | PASS | 1.34 |
