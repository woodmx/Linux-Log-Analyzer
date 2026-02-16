#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_PATH = "sample.log" 
THRESHOLD = 3

def analyze_log():
	failed_attempts = defaultdict(int)

	with open(LOG_PATH, "r") as log_file:
		for line in log_file:
			if "Failed password" in line:
				match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
				if match:
					ip = match.group(1)
					failed_attempts[ip] += 1
	
	print("\n--- Failed Login Report ---\n")

	for ip, count in failed_attempts.items():
		print(f"{ip} -> {count} failed attempts")
		if count >= THRESHOLD:
			print("Suspicious activity detected!")

if __name__ == "__main__":
	analyze_log()
