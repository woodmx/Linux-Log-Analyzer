# Linux Failed Login Analyzer
A simple cybersecurity-focused Python tool that analyzes Linux authentication logs and detects suspicious failed SSH login attempts.


## Features
- Parses /var/log/auth.log (sample.log)
- Extracts IP addresses from failed login attempts
- Counts number of failures per IP
- Flags suspicious activity (5+ attempts)


## Usage

```bash
sudo python3 log_analyzer.py

```


## Why I Built This
This project demonstrates practical Linux security monitoring by analyzing SSH authentication logs to detect suspicious failed login attempts.

It highlights skills in:
- Python scripting
- Regular expressions
- Log parsing
- Basic intrusion detection concepts
- Working in a Linux environment
