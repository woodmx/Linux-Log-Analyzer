import re


LOG_PATH = "data/sample.log"
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

    reportLines = []

    reportLines.append("LINUX FAILED LOGIN REPORT")
    reportLines.append("-------------------------")
    reportLines.append(f"Log File: {LOG_PATH}")
    reportLines.append(f"Suspicious Threshold: {THRESHOLD} failed attempts")
    reportLines.append("")

    reportLines.append(f"Total Failed Login Attempts: {totalFailedAttempts}")
    reportLines.append(f"Unique Source IPs: {uniqueSourceIps}")
    reportLines.append("")

    reportLines.append("TOP SOURCE IPs")
    reportLines.append("--------------")

    if failedAttempts:
        for ipAddress, attemptCount in sorted(
            failedAttempts.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            reportLines.append(f"{ipAddress} -> {attemptCount} failed attempts")
    else:
        reportLines.append("No failed login attempts found.")

    reportLines.append("")
    reportLines.append("SECURITY STATUS")
    reportLines.append("---------------")

    if suspiciousIps:
        reportLines.append("Suspicious activity detected from:")
        for ipAddress in suspiciousIps:
            reportLines.append(ipAddress)
    else:
        reportLines.append("No suspicious activity detected.")

    reportText = "\n".join(reportLines)

    print(reportText)

    saveReport(reportText)


# Saves printed report
def saveReport(reportText):
    reportPath = "reports/analysis_report.txt"

    try:
        with open(reportPath, "w", encoding="utf-8") as reportFile:
            reportFile.write(reportText)

        print()
        print(f"Report saved to: {reportPath}")

    except Exception as errorMessage:
        print(f"Error writing report: {errorMessage}")



# Main program
def main():
    logLines = readLogFile(LOG_PATH)

    if not logLines:
        return

    failedAttempts = extractFailedLoginIps(logLines)
    printReport(failedAttempts)


main()
