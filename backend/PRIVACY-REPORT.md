# CodeShield AI — Privacy Report (O-05 / NFR-02)

- Static egress audit: **PASS — no cloud hosts / non-local URLs in code**
- Defaults: Ollama `http://localhost:11434/v1` + `codellama:7b-instruct` PASS (local-only)
- Dynamic (M5 demo): run a full scan-to-AI-fix session, capture with:
  `tshark -i any -f "tcp port 80 or tcp port 443" -a duration:120 -w m5-capture.pcapng`
  then confirm no packets with source-content payloads leave localhost.
  Expected: only loopback traffic to :8000 (backend) and :11434 (Ollama).
