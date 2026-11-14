# OSV verification for 0.1.60

The Windows package was extracted into an isolated test directory. Its windowed backend executable started with CREATE_NO_WINDOW and returned HTTP 200 from /health with version 0.1.60. A request to /dependency-advisories for synthetic django==3.2.1 returned one finding containing CVE aliases.

A VS Code Extension Development Host loaded the extracted package with a separate user profile and workspace. OSV enrichment was enabled in that profile. The osvEditor.cjs test invoked secureCoding.scanCurrentFile and read vscode.languages.getDiagnostics for requirements.txt. It observed CS-A03-OSV containing CVE references on line zero of the expected file URI. This verifies the asynchronous response was published through DiagnosticCollection.set for the target document.

The advisoryUpdate.test.cjs tests verify that edits and newer scans prevent delayed advisory responses from overwriting diagnostics. Backend regression tests exercise OSV HTTP 500 and timeout fallback using mock HTTP transport.

Verification results were 53/53 backend regression checks, 3/3 advisory publication tests, a successful TypeScript compile and a passing editor test. The existing synthetic evaluation retained 25/25 expected detections and all 12 negative probes. Backend regression checks completed outside the command sandbox after the sandboxed invocation stalled.

To inspect the same flow manually, enable secureCoding.osvAdvisories in user settings, open a trusted workspace containing requirements.txt with django==3.2.1, and run Secure Coding: Scan Current File. Open View → Output and choose CodeShield Workspace Scan. Follow entries tagged CS-A03-OSV from request through response to published diagnostics. The CodeShield channel reports backend startup. OSV sends dependency coordinates over the network and its availability can affect live results.

The earlier missing editor result cannot independently establish a single historical cause. The reported Uvicorn formatter crash prevents that backend process from serving requests. The packaged process and editor response path now both pass the described test.
