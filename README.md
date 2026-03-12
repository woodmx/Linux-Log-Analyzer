# Linux Security Log Analyzer

A Python tool that analyzes Linux SSH authentication logs to detect suspicious login activity.

This project demonstrates basic security monitoring by parsing log files and identifying repeated failed login attempts from the same IP address.

---

## Features

- Parses SSH authentication logs
- Detects failed login attempts
- Aggregates failed attempts by source IP
- Flags suspicious IPs that exceed a configurable threshold
- Displays a clear security report

---

## Example Output

```
LINUX FAILED LOGIN REPORT
-------------------------
Log File: sample.log
Suspicious Threshold: 5 failed attempts

Total Failed Login Attempts: 7
Unique Source IPs: 3

TOP SOURCE IPs
--------------
203.0.113.10 -> 5 failed attempts
198.51.100.25 -> 1 failed attempts
192.0.2.50 -> 1 failed attempts

SECURITY STATUS
---------------
Suspicious activity detected from:
203.0.113.10
```

---

## Sample Log File

This repository includes a sanitized `sample.log` file that mimics Linux SSH authentication logs.

The IP addresses use **documentation-only ranges**:

- `192.0.2.x`
- `198.51.100.x`
- `203.0.113.x`

These are reserved for examples and do not represent real systems.

---

## How It Works

The analyzer processes a log file that contains SSH authentication events.

The script performs the following steps:

1. Reads the log file line by line.
2. Searches for entries containing `Failed password`, which indicate unsuccessful SSH login attempts.
3. Uses a regular expression to extract the source IP address from each failed login attempt.
4. Counts how many failed login attempts originate from each IP address.
5. Compares the number of attempts against a configurable threshold.
6. Flags any IP address that exceeds the threshold as suspicious.

The final report summarizes:

- total failed login attempts
- number of unique source IP addresses
- top attacking IPs
- whether suspicious activity was detected

The IP address is extracted using a regular expression:

`from (\d+\.\d+\.\d+\.\d+)`


---

## Running the Analyzer

Run the script from the project directory:

```bash
python3 log_analyzer.py
```

---

## Security Note

This repository intentionally excludes sensitive data.

The project does **not include**:

- real system authentication logs
- logs from production systems
- private keys or credentials
- internal hostnames or network addresses

The included `sample.log` file is **sanitized and safe for public repositories**.  
All IP addresses use documentation-only ranges reserved for examples:

- `192.0.2.x`
- `198.51.100.x`
- `203.0.113.x`

These IP ranges are defined in **RFC 5737** and are commonly used for documentation and training examples.


---

## Possible Future Improvements

Future enhancements could expand the analyzer into a more complete security monitoring tool:

- detect successful logins following repeated failures
- identify time-based attack patterns
- export analysis results to a report file
- support additional log formats
- build a command-line interface for configurable analysis
