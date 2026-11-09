# CodeShield AI — Performance Evidence

- The previous AI benchmark recorded 5/10 non-empty patches and approximately 90-second latency. It predates the current AI-fix changes and is retained as historical evidence only.
- AI end-to-end latency and patch quality have **not** been remeasured against version 0.1.29 or the current source. No claim is made here that the latest version meets an AI latency or applicability target.
- Current offline scanner latency and synthetic-case results are regenerated in `EVAL-REPORT.md` by `app/evaluate.py`.
- The backend test suite was rerun after the scanner/context changes; see the submission checklist for the current count.
- A live-model benchmark should record provider/model, hardware, prompt size, response validity, syntax validity, scanner outcome, latency, and whether a built-in fallback was used. Do not mix template fallback timings with model response timings.
