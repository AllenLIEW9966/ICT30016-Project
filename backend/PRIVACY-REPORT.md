# CodeShield AI — Privacy Report

## Current behavior

- Local scanning runs through the local extension/backend pipeline.
- Ollama is the default AI provider. In this mode, code context is sent only to the local Ollama service.
- Optional free-tier cloud choices are Groq, Gemini, and OpenRouter. When a user requests an AI fix, the bounded context for that finding is sent through the local backend to the selected provider.
- Cloud API keys are stored in VS Code SecretStorage. They are passed through the local backend for a request and are not written to application settings by the extension.
- Free-tier quotas, model availability, and provider data policies vary and can change. Google may use content submitted through its free tier to improve its products.
- The custom OpenAI-compatible endpoint is user-configured and may incur charges. Remote custom endpoints must use HTTPS; HTTP is accepted only for loopback endpoints.

## Verification status

- A packet-capture verification of local and cloud modes has not yet been recorded.
- Zero-egress applies only to the local Ollama configuration; cloud AI sends code context to the selected provider.
- Before release, capture a local-only session and a cloud session separately, verify their destinations, and update this report with the date and evidence.
