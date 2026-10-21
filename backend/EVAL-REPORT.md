# CodeShield AI — Evaluation Report (M2/M3/M2.5, NFR-01)

- Corpus: 30 cases (21 TP, 9 negatives)
- M2 detection: **21/21 = 100.0%** PASS (>80%)
- M3 FP reduction: raw=2 validated=0 reduction=**100.0%** PASS (>50%); TP retained raw=12 validated=12
- M2.5 patch applicability: **18/21 = 85.7%** PASS (>70%) (mode=template/quick)
- NFR-01 static latency: p50=0.2ms p95=2.1ms max=3.3ms PASS (<100ms)

## Per-case

| id | lang | expect | got | pass | ms |
|---|---|---|---|---|---|
| PY-TP-01 | python | PY-SQLI-001 | PY-SQLI-001 | PASS | 2.12 |
| PY-TP-02 | python | PY-SQLI-001 | PY-SQLI-001 | PASS | 0.21 |
| PY-TP-03 | python | PY-CMD-001 | PY-CMD-001 | PASS | 0.13 |
| PY-TP-04 | python | PY-SECRETS-001 | PY-SECRETS-001 | PASS | 0.07 |
| PY-TP-05 | python | PY-PATH-001 | PY-PATH-001 | PASS | 0.11 |
| PY-TP-06 | python | PY-SSRF-001 | PY-SSRF-001 | PASS | 0.1 |
| PY-TP-07 | python | PY-SERIAL-001 | PY-SERIAL-001 | PASS | 0.09 |
| PY-TP-08 | python | PY-CODE-EXEC-001 | PY-CODE-EXEC-001 | PASS | 0.06 |
| PY-TP-09 | python | PY-CODE-EXEC-002 | PY-CODE-EXEC-002 | PASS | 0.05 |
| PY-TP-10 | python | PY-CRYPTO-001 | PY-CRYPTO-001 | PASS | 0.09 |
| PY-TP-11 | python | PY-CRYPTO-002 | PY-CRYPTO-002 | PASS | 0.08 |
| PY-TP-12 | python | PY-CONFIG-001 | PY-CONFIG-001 | PASS | 0.05 |
| PY-FP-01 | python | None |  | PASS | 0.04 |
| PY-FP-02 | python | None |  | PASS | 0.04 |
| PY-FP-03 | python | None |  | PASS | 0.08 |
| PY-FP-04 | python | None |  | PASS | 0.12 |
| PY-FP-05 | python | None |  | PASS | 0.06 |
| JS-TP-01 | javascript | JS-CODE-EXEC-001 | JS-CODE-EXEC-001 | PASS | 3.25 |
| JS-TP-02 | javascript | JS-CODE-EXEC-002 | JS-CODE-EXEC-002 | PASS | 1.53 |
| JS-TP-03 | javascript | JS-SQLI-001 | JS-SQLI-001 | PASS | 2.36 |
| JS-TP-04 | javascript | JS-XSS-001 | JS-XSS-001 | PASS | 1.35 |
| JS-TP-05 | javascript | JS-XSS-001 | JS-XSS-001 | PASS | 1.09 |
| JS-TP-06 | javascript | JS-RANDOM-001 | JS-RANDOM-001 | PASS | 1.49 |
| JS-TP-07 | javascript | JS-SECRETS-001 | JS-SECRETS-001 | PASS | 0.89 |
| JS-TP-08 | javascript | JS-CONFIG-001 | JS-CONFIG-001 | PASS | 0.81 |
| JS-TP-09 | javascript | JS-JWT-001 | JS-JWT-001 | PASS | 1.1 |
| JS-FP-01 | javascript | None |  | PASS | 1.04 |
| JS-FP-02 | javascript | None |  | PASS | 1.28 |
| JS-FP-03 | javascript | JS-CRYPTO-001 |  | PASS | 0.95 |
| JS-FP-04 | javascript | None |  | PASS | 0.55 |
