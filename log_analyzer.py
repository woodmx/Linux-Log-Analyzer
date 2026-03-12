import re


LOG_PATH = "sample.log"
THRESHOLD = 5


# Reads the log file safely
def readLogFile(filePath):
    try:
        with open(filePath, "r", encoding="utf-8") as logFile:
            return logFile.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{filePath}' was not found.")
        return []
    except Exception as errorMessage:
        print(f"Error reading log file: {errorMessage}")
        return []


# Extracts failed login IP addresses from log lines
def extractFailedLoginIps(logLines):
    failedAttempts = {}

    for lineText in logLines:
        if "Failed password" in lineText:
            matchObject = re.search(r"from (\d+\.\d+\.\d+\.\d+)", lineText)

            if matchObject:
                ipAddress = matchObject.group(1)

                if ipAddress in failedAttempts:
                    failedAttempts[ipAddress] += 1
                else:
                    failedAttempts[ipAddress] = 1

    return failedAttempts


# Builds a list of suspicious IPs based on the threshold
def getSuspiciousIps(failedAttempts):
    suspiciousIps = []

    for ipAddress, attemptCount in failedAttempts.items():
        if attemptCount >= THRESHOLD:
            suspiciousIps.append(ipAddress)

    return suspiciousIps


# Prints a formatted report
def printReport(failedAttempts):
    totalFailedAttempts = sum(failedAttempts.values())
    uniqueSourceIps = len(failedAttempts)
    suspiciousIps = getSuspiciousIps(failedAttempts)

    print("LINUX FAILED LOGIN REPORT")
    print("-------------------------")
    print(f"Log File: {LOG_PATH}")
    print(f"Suspicious Threshold: {THRESHOLD} failed attempts")
    print()

    print(f"Total Failed Login Attempts: {totalFailedAttempts}")
    print(f"Unique Source IPs: {uniqueSourceIps}")
    print()

    print("TOP SOURCE IPs")
    print("--------------")

    if failedAttempts:
        for ipAddress, attemptCount in sorted(
            failedAttempts.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"{ipAddress} -> {attemptCount} failed attempts")
    else:
        print("No failed login attempts found.")

    print()
    print("SECURITY STATUS")
    print("---------------")

    if suspiciousIps:
        print("Suspicious activity detected from:")
        for ipAddress in suspiciousIps:
            print(ipAddress)
    else:
        print("No suspicious activity detected.")


# Main program
def main():
    logLines = readLogFile(LOG_PATH)

    if not logLines:
        return

    failedAttempts = extractFailedLoginIps(logLines)
    printReport(failedAttempts)


main()
