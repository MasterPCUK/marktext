# Security Audit Utilities

This repository now includes a lightweight static scanner that surfaces potential security red flags such as hard-coded domains, IP addresses, or obfuscated data blobs. The tool does not make any changes – it simply reports findings that should be reviewed by a human.

## Usage

```bash
yarn audit:security
```

The command runs `tools/securityAudit.js` from the repository root. Exit code `0` indicates no findings, while a non-zero exit code means that potential issues were detected. The script intentionally errs on the side of caution and may report false positives (for example, documentation links or SVG path data that resemble IP addresses). By default the scanner skips documentation and test directories to reduce noise; adjust the `ignoreDirectories` list at the top of the script if you need to include them.

### Interpreting Results

Each finding prints:

- the file path and line number,
- the matched string, and
- a short description of why it was flagged.

The summary at the end of the run groups findings by category so that you can quickly see whether new warnings appeared after a change.

When reviewing the report, verify that all external domains and IP addresses are expected (e.g., official APIs, documentation, or localhost). Obfuscated or base64-encoded strings should be explained by comments or known assets. If something is unexpected, investigate further before shipping.

## Current Status

Running the tool against the current workspace highlights only known-safe references such as documentation links, localhost bindings, and encoded data used in markdown and PlantUML helpers. No malicious or unknown endpoints were discovered.
