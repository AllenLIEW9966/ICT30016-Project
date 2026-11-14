# CodeShield AI — Presentation Outline

Release 0.1.60. This outline follows the supplied 12-slide `CodeShield_AI_ICT30016_Presentation.pptx`, retaining its topic order. The supplied deck predates P1, so the suggested slide wording below updates its OSV, architecture and evaluation claims. The source PPTX is preserved.

The English speaking notes use simple language for the academic/industry panel. Allow 14 minutes for content and recorded demonstrations, one minute for transitions, and a separate five minutes for Q&A. Speaking allocations are a proposal for the four team members and do not assert implementation ownership.

| Presenter | Slides | Content time | Focus |
|---|---|---|---|
| Lee Kok Kiong | 1–3 | 3 minutes | Problem and architecture |
| Allen Liew Kang Quan | 4–6 | 4 minutes | Implementation and A05 fixing workflow |
| Jee Zi Qian | 7–9 | 4 minutes | Privacy, evaluation and A03 demo |
| Jezzper Kueh Zhe Yu | 10–12 | 3 minutes | Requirement fit, limits and handover |

## Slide 1 — CodeShield AI

Time: 45 seconds. Keep the supplied title and team credits.

**Say**

“Good morning. CodeShield AI brings security warnings and guided fixes into VS Code while developers write Python and JavaScript. We will show how it finds selected security risks, explains them and helps developers review a fix. We will also show our new dependency advisory feature and the limits of the prototype.”

## Slide 2 — Security feedback, while you code

Time: 60 seconds. Retain the template's timely feedback, actionable findings and developer control points.

Show a 15-second clip within this slot of an unsaved Python edit receiving a finding.

**Say**

“Developers need clear feedback while they are working. CodeShield updates supported findings as files are opened or edited. The message includes the risk, severity and a suggestion. Developers can inspect the warning in the same editor and decide which fix path to use.”

## Slide 3 — Local analysis and asynchronous enrichment

Time: 75 seconds. Use the template's local/external boundary diagram to show both channels.

Update its current footer, “Detection stays local. AI only fixes; it never creates findings.” Suggested footer wording is “Local source checks run automatically. Optional OSV adds dependency findings. AI Fix runs on request.” Add an OSV branch labelled “Package coordinates → OSV → CS-A03-OSV” alongside the optional cloud AI branch.

**Say**

“There are two channels. The local channel sends code to our FastAPI backend, where Python AST rules and JavaScript analysis create findings. The second channel adds optional services asynchronously. OSV checks known advisories for dependency versions when enabled. AI helps with a fix when the developer asks. Ollama can run on the laptop, while cloud models receive the approved code context. Related project files can be included through a separate choice.”

## Slide 4 — Extension and backend

Time: 60 seconds. Retain the implementation layout and the 2,000-file and 512 KiB limits.

Correct the original backend/context wording to “Extension maintains the local context cache. FastAPI runs analysis and provider requests.” Keep Python AST, JavaScript Babel AST and pattern fallback visible.

**Say**

“The extension handles editor events, diagnostics, fix commands and a local cache of selected project files. FastAPI runs the scanners and talks to external services when requested. Workspace scanning checks files individually. It is bounded to 2,000 files and skips files larger than 512 KiB, along with common generated folders. The context cache helps a requested AI fix use relevant project information.”

## Slide 5 — A05 from code to finding

Time: 90 seconds, including a 20–30-second clip. Reuse the code-and-finding layout.

Show `PY-SQLI-001`, Critical, CWE-89 and OWASP A05:2025 Injection. If displaying the 2021 crosswalk, use A03:2021 Injection. Use the README SQL fixture in the recording and display the actual hover. Label the code as a synthetic fixture.

**Say**

“Here, a username is inserted directly into a SQL string. The scanner flags the execution call as a possible SQL injection. The finding shows its rule ID, Critical severity, CWE-89 and OWASP category. The suggestion is to bind the input as a parameter, keeping the supplied value separate from SQL syntax.”

## Slide 6 — Three ways to fix

Time: 90 seconds, including a 30–40-second clip of preview, approval and rescan. Retain the comparison table.

Update the original statement “Detection is always static” to “Local rules and optional OSV create findings. AI generates requested fixes.”

**Say**

“Quick Fix handles one supported deterministic change. Fix All applies supported deterministic changes in the current file. AI Fix asks the selected model to prepare a patch using the available context. We check its syntax and scan the candidate again before offering to apply it. The developer reviews the diff, approves the change and runs project tests. A passing scan alone cannot prove that the program still behaves correctly.”

Demonstrate AI Fix only if a validated candidate is available. If generation fails, show its actual result briefly and complete the SQL example using the verified parameterized edit in the README.

## Slide 7 — You choose where data goes

Time: 60 seconds. Retain the provider/privacy slide and include OSV in its boundaries.

Replace “Scanning and context caching stay local” with “Source analysis and context caching stay local. Optional OSV sends dependency coordinates.” Retain SecretStorage, best-effort redaction and outstanding cloud privacy verification.

**Say**

“Ollama runs locally. Cloud models require the user's API key and receive code during a requested fix. Including related project files is a separate choice. API keys use VS Code SecretStorage, and redaction helps remove common secret patterns. OSV receives package names and versions when its setting is enabled. Users still need to review sensitive content and service terms.”

## Slide 8 — Evaluation results

Time: 75 seconds. Retain the metrics layout and the prominent small-synthetic-corpus caveat.

Show 53/53 backend regression checks, 3/3 asynchronous publication checks, and an editor OSV test passed. Retain 25/25 expected detections and 12/12 negative probes as a separate corpus result. Remove the old 2.7 ms latency claim unless the team presents the specific run that produced it.

**Say**

“The release passed 53 backend regression checks and three tests that prevent delayed advisory results from overwriting newer edits. We also verified OSV diagnostics in a real VS Code development host using the packaged extension. The separate synthetic corpus passed 25 expected detections and 12 negative probes. These are selected examples. They do not establish broad real-world detection, full OWASP coverage or the quality of every AI model.”

## Slide 9 — A03 dependency advisory demo

Time: 105 seconds, including a 40–50-second recorded clip. Adapt the existing four-stage timeline.

1. **Enable and scan** — enable `secureCoding.osvAdvisories` in user settings and scan `requirements.txt` containing `django==3.2.1` in a trusted workspace.
2. **Explain** — show `CS-A03-OSV` and the CVE identifiers attached to that dependency line.
3. **Inspect the response** — show `CodeShield Workspace Scan` Output entries for request, response and diagnostic publication.
4. **Show the boundary** — explain that a timeout preserves offline findings and a dependency upgrade needs compatibility testing. Do not claim an automatic safe version upgrade.

**Say**

“This manifest declares an older Django version. We scan the file with OSV enabled. The backend checks its package coordinates online, then the extension adds an advisory finding to the correct line. Here are its CVE references and the request-to-publication log. This lookup runs separately from local scanning. Our tests cover service errors, timeouts and edits made while a response is pending. Choosing a replacement version still needs compatibility checks.”

Record online waiting time in advance. If a shortened clip skips the wait, label it “Waiting time shortened.” Current CVE counts can change, so avoid promising a fixed list length.

## Slide 10 — Requirement fit and impact

Time: 60 seconds. Reuse the requirements table. Add optional A03 advisories to the delivered functionality and retain partial detection/install status.

**Say**

“The prototype combines static analysis with contextual AI suggestions, supports Python and JavaScript and works inside VS Code. Findings include OWASP and CWE explanations. Its useful additions include online dependency advisories, a local or cloud model choice and optional project context. These features can reduce the steps needed to understand and review a fix. False positives, missed risks and incorrect AI patches can also cost time or create false confidence.”

## Slide 11 — Limits and future work

Time: 60 seconds. Retain the delivered/future-work layout, with P1 OSV in delivered work.

Show file-local analysis, selected patterns and limited evaluation clearly. Future work includes one-hop cross-file SQL flow, a larger attributed corpus, a coverage TreeView, and broader platform/privacy testing.

**Say**

“Our checks cover selected patterns across the OWASP categories. They cannot prove an application is secure or infer its authorization policy. AI can produce incomplete or behavior-changing patches. We also need broader evaluation and platform testing. Next, we plan bounded analysis across related files, more realistic test examples and a category view built from existing findings.”

## Slide 12 — Handover and questions

Time: 60 seconds. Retain the closing design, prototype boundary and panel questions.

Show the Windows 0.1.60 VSIX, source repository, README demo guide and evaluation report as the handover items. macOS packages are obtained through successful CI builds and need platform validation. Leave five minutes after the presentation for questions.

**Say**

“Our handover includes the Windows installer, source code, setup guide and evaluation evidence. The developer can follow a warning through explanation, patch review and rescan. The prototype needs further validation before production use. We welcome your feedback on which framework support and test evidence should come next.”

## Recording and rehearsal checklist

- Use a separate trusted demo workspace and synthetic code. Keep actual keys, personal paths and unrelated notifications out of recordings.
- Prepare the backend, chosen AI model and OSV access before recording. Capture the visible extension version as 0.1.60.
- Embed clips on slides 2, 5, 6 and 9. Their playback is included in each slide's timing. Avoid a second full-length demo in the same presentation.
- Use exact command names from the README and confirm each recorded patch. A rejected candidate is a limitation demonstration, not an applied fix.
- Rehearse to 14 minutes plus transitions. Keep a short recording of the successful OSV result available if a live service is unavailable.

## Likely panel questions

**Does this cover all OWASP vulnerabilities?** Selected checks have labels across A01–A10. Equivalent vulnerabilities and unimplemented cases can be missed.

**Is the AI reviewing the workspace continuously?** The extension maintains a local context cache. The model receives selected context when AI Fix is requested. Local rules and optional OSV generate findings.

**Why can a candidate be rejected?** It may have invalid syntax, retain a flagged risk, introduce an unsafe change or require project information. Model choice and context can affect the proposal, while validation checks only part of correctness.

**What happens offline?** Local scanning remains available. Online advisories and cloud AI depend on network access. Ollama also needs an installed, running model.

**What is new in P1?** Optional exact-version OSV lookup, six-hour caching, fallback on network failure, protection against stale diagnostic publication and tested Windows 0.1.60 packaging.
