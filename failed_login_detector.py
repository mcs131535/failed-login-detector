import re
import csv
import argparse
import os
from datetime import datetime, timedelta
from collections import defaultdict


# Command-line arguments
parser = argparse.ArgumentParser(
    description="Detect suspicious failed login activity."
)

parser.add_argument(
    "--window",
    type=int,
    default=5,
    help="Time window in minutes (default: 5)"
)

parser.add_argument(
    "--threshold",
    type=int,
    default=3,
    help="Minimum failed attempts required for an alert (default: 3)"
)

parser.add_argument(
    "--input",
    default="sample_auth.log",
    help="Input authentication log file (default: sample_auth.log)"
)

parser.add_argument(
    "--output",
    default="alerts.csv",
    help="Output CSV file (default: alerts.csv)"
)

parser.add_argument(
    "--success-window",
    type=int,
    default=10,
    help="Time window in minutes for correlating successful logins (default: 10)"
)

args = parser.parse_args()

# Validate command-line arguments
if args.window <= 0:
    print("ERROR: The time window must be greater than 0 minutes.")
    exit()

if args.threshold <= 0:
    print("ERROR: The threshold must be greater than 0.")
    exit()

if args.success_window <= 0:
    print("ERROR: The success window must be greater than 0 minutes.")
    exit()


if not os.path.isfile(args.input):
    print(f"ERROR: Input file '{args.input}' was not found.")
    print("Please check the file path and try again.")
    exit()

TIME_WINDOW_MINUTES = args.window
LOG_FILE = args.input
OUTPUT_FILE = args.output

# Detection thresholds
MEDIUM_THRESHOLD = args.threshold
HIGH_THRESHOLD = 5
CRITICAL_THRESHOLD = 10
LOG_FILE = args.input
OUTPUT_FILE = args.output

# Example:
# 2026-09-29 08:01:12 FAILED_LOGIN user=admin src_ip=192.168.1.25

pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"FAILED_LOGIN user=(?P<user>\S+) "
    r"src_ip=(?P<ip>\S+)"
)

success_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"SUCCESS_LOGIN user=(?P<user>\S+) "
    r"src_ip=(?P<ip>\S+)"
)

failed_attempts = defaultdict(list)
successful_logins = defaultdict(list)

# --------------------------------------------------
# Read authentication log
# --------------------------------------------------

with open(LOG_FILE, "r") as file:

    for line in file:

        # Check for failed login
        match = pattern.search(line)

        if match:

            timestamp = datetime.strptime(
                match.group("timestamp"),
                "%Y-%m-%d %H:%M:%S"
            )

            username = match.group("user")
            ip_address = match.group("ip")

            failed_attempts[ip_address].append(
                {
                    "timestamp": timestamp,
                    "username": username
                }
            )

            continue

        # Check for successful login
        success_match = success_pattern.search(line)

        if success_match:

            timestamp = datetime.strptime(
                success_match.group("timestamp"),
                "%Y-%m-%d %H:%M:%S"
            )

            username = success_match.group("user")
            ip_address = success_match.group("ip")

            successful_logins[ip_address].append(
                {
                    "timestamp": timestamp,
                    "username": username
                }
            )


alerts = []

# --------------------------------------------------
# Analyze authentication activity
# --------------------------------------------------

for ip_address, attempts in failed_attempts.items():

    attempts.sort(key=lambda x: x["timestamp"])

    i = 0

    while i < len(attempts):

        window_start = attempts[i]["timestamp"]
        window_end = window_start + timedelta(
            minutes=TIME_WINDOW_MINUTES
        )

        window_attempts = []

        for attempt in attempts[i:]:
            if attempt["timestamp"] <= window_end:
                window_attempts.append(attempt)
            else:
                break

        attempt_count = len(window_attempts)

        # Do not generate an alert unless
        # the minimum threshold is reached.
        if attempt_count < MEDIUM_THRESHOLD:
            i += 1
            continue

        usernames = sorted(
            set(
                attempt["username"]
                for attempt in window_attempts
            )
        )

        # Determine severity
        if attempt_count >= CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif attempt_count >= HIGH_THRESHOLD:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # Determine attack type
        if len(usernames) >= 3:
            attack_type = "Possible Password Spraying"
        elif len(usernames) == 1:
            attack_type = "Possible Brute Force"
        else:
            attack_type = "Multiple Account Targeting"

    

        # --------------------------------------------------
        # Determine severity
        # --------------------------------------------------

        if attempt_count >= CRITICAL_THRESHOLD:
            severity = "CRITICAL"

        elif attempt_count >= HIGH_THRESHOLD:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        # --------------------------------------------------
        # Determine attack pattern
        # --------------------------------------------------

        if len(usernames) >= 3:
            attack_type = "Possible Password Spraying"

        elif len(usernames) == 1:
            attack_type = "Possible Brute Force"

        else:
            attack_type = "Multiple Account Targeting"

                      # Check for successful login after suspicious failures
        successful_login = False

        for login in successful_logins.get(ip_address, []):

            if (
                window_attempts[0]["timestamp"]
                <= login["timestamp"]
                and login["timestamp"]
                <= window_attempts[-1]["timestamp"] + timedelta(minutes=args.success_window)
                and login["username"] in usernames
            ):
                successful_login = True
                break

    

               # Check for successful login after suspicious failures
        successful_login = False

        for login in successful_logins.get(ip_address, []):

            if (
                window_attempts[0]["timestamp"]
                <= login["timestamp"]
                and login["timestamp"]
                <= window_attempts[-1]["timestamp"] + timedelta(minutes=10)
                and login["username"] in usernames
            ):
                successful_login = True
                break

        # Calculate risk score
        risk_score = 0

        if severity == "MEDIUM":
            risk_score += 30

        elif severity == "HIGH":
            risk_score += 60

        elif severity == "CRITICAL":
            risk_score += 80

        if successful_login:
            risk_score += 20

        if attack_type == "Possible Password Spraying":
            risk_score += 10

        if risk_score > 100:
            risk_score = 100

        alert = {
            "source_ip": ip_address,
            "attempts": attempt_count,
            "first_seen": window_attempts[0]["timestamp"],
            "last_seen": window_attempts[-1]["timestamp"],
            "usernames": ", ".join(usernames),
            "severity": severity,
            "attack_type": attack_type,
            "successful_login": "YES" if successful_login else "NO",
            "risk_score": risk_score
        }

        if alert not in alerts:
            alerts.append(alert)

        i += len(window_attempts)


# --------------------------------------------------
# Display results
# --------------------------------------------------

print("\n=== PYTHON FAILED LOGIN DETECTOR ===\n")

if not alerts:

    print("No suspicious authentication activity detected.")

else:

    print(f"ALERTS DETECTED: {len(alerts)}\n")

    for alert in alerts:

        print(f"Severity:     {alert['severity']}")
        print(f"Attack Type:  {alert['attack_type']}")
        print(f"Source IP:    {alert['source_ip']}")
        print(f"Attempts:     {alert['attempts']}")
        print(f"Users:        {alert['usernames']}")
        print(f"First Seen:   {alert['first_seen']}")
        print(f"Last Seen:    {alert['last_seen']}")
        print("-" * 45)


# --------------------------------------------------
# Export results to CSV
# --------------------------------------------------

with open(OUTPUT_FILE, "w", newline="") as file:

    fieldnames = [
    "source_ip",
    "attempts",
    "first_seen",
    "last_seen",
    "usernames",
    "severity",
    "attack_type",
    "successful_login",
    "risk_score"
]
    

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(alerts)


print(f"\nResults saved to {OUTPUT_FILE}")