# Build Notes — Linux Security Log Analyzer

## Project Goal
Create a simple Python tool that analyzes SSH authentication logs to identify suspicious login activity.

The tool scans log entries, extracts source IP addresses from failed login attempts, and highlights IPs that exceed a configurable threshold.

---

## Design Decisions

### Python
Python was chosen because it is widely used for automation, scripting, and log analysis in system administration and cybersecurity workflows.

### Regular Expressions
The script uses a regular expression to extract IPv4 addresses from log lines:

`from (\d+\.\d+\.\d+\.\d+)`

This allows the analyzer to reliably capture the source IP from failed SSH login attempts.

### Threshold-Based Detection
A configurable threshold is used to flag suspicious activity.

Threshold = 5

This value reflects common brute-force detection patterns where repeated failures from the same source may indicate automated login attempts.

### Sanitized Sample Log
The repository includes a **sanitized example log file** so the project can be shared publicly without exposing sensitive information.

The sample log uses documentation IP ranges:

- 192.0.2.x
- 198.51.100.x
- 203.0.113.x

These ranges are reserved for examples and training environments.

---

## Development Workflow

The project was built incrementally using small commits:

1. Created repository structure
2. Implemented log parsing
3. Added IP aggregation logic
4. Added suspicious activity detection
5. Created sanitized example log
6. Improved documentation

This approach mirrors real-world development practices where features are added and tested incrementally.

---

## Future Expansion Ideas

The analyzer could be expanded with additional capabilities:

- detect successful logins following repeated failures
- track time-based attack patterns
- export reports to files
- add command-line arguments for configuration
- support multiple log formats
