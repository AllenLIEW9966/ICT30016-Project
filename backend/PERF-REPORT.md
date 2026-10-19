# CodeShield AI — Perf Report (NFR-01 AI, NFR-03 memory, M4)

- AI patch mode: template-fallback (5/10 ok)
- AI latency: p50=90010.4ms p95=90031.7ms max=90042.8ms CHECK (needs live Ollama on GPU)
- Backend RSS: 34.3 MB; JS worker RSS: 15.5 MB (cap 6000 MB) PASS
- M4: extension `npm run compile` clean; backend tests 26/26; debounce 500ms; scan p50<5ms (see EVAL-REPORT.md).
