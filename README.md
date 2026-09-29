# Python Failed Login Detector

A Python-based security log analysis tool that detects suspicious authentication activity, identifies potential brute-force and password-spraying behavior, correlates suspicious failed logins with subsequent successful authentication, and assigns risk scores to security alerts.

This project was built as a hands-on cybersecurity portfolio project to demonstrate practical skills in **Python scripting, security log analysis, detection engineering, event correlation, risk assessment, and SOC alert triage**.

## Overview

Authentication logs can contain thousands of events, making it difficult for security analysts to identify meaningful attack patterns manually.

This tool analyzes authentication events and looks for repeated failed logins within a configurable time window. It then evaluates the behavior, assigns a severity level, identifies the potential attack type, checks for a subsequent successful login, and calculates a 0–100 risk score.

The goal is to demonstrate how basic security automation can help an analyst identify and prioritize suspicious authentication activity.

## Features

* Parses failed and successful authentication events
* Detects repeated failed-login activity
* Identifies potential brute-force attacks
* Identifies potential password-spraying attacks
* Identifies multiple-account targeting
* Assigns MEDIUM, HIGH, or CRITICAL severity
* Correlates suspicious failures with subsequent successful authentication
* Calculates a 0–100 risk score
* Supports configurable detection thresholds
* Supports configurable detection windows
* Supports configurable successful-login correlation windows
* Validates command-line input
* Detects missing input files
* Exports structured security alerts to CSV
* Reduces false positives by evaluating authentication failures as time-based patterns

## Technologies

* Python 3
* Regular Expressions
* CSV
* `argparse`
* `datetime`
* `collections`
* Windows Command Prompt
* Visual Studio Code
* Git / GitHub

## Detection Logic

The detector groups authentication failures by source IP and evaluates them within a configurable time window.

### Brute Force Detection

Multiple failed authentication attempts against the same username are classified as:

`Possible Brute Force`

### Password Spraying Detection

Failed authentication attempts against three or more different usernames from the same source IP are classified as:

`Possible Password Spraying`

### Multiple Account Targeting

Activity involving multiple usernames that does not meet the password-spraying threshold is classified as:

`Multiple Account Targeting`

## Severity

The number of failed attempts determines the initial alert severity.

| Failed Attempts | Severity |
| --------------: | -------- |
|             3–4 | MEDIUM   |
|             5–9 | HIGH     |
|             10+ | CRITICAL |

## Risk Scoring

The tool calculates a risk score between 0 and 100.

| Condition                                      | Score |
| ---------------------------------------------- | ----: |
| MEDIUM severity                                |   +30 |
| HIGH severity                                  |   +60 |
| CRITICAL severity                              |   +80 |
| Successful login following suspicious failures |   +20 |
| Possible password spraying                     |   +10 |
| Maximum score                                  |   100 |

The score is capped at 100.

### Example

A HIGH-severity brute-force alert normally receives:

`60`

If the targeted account subsequently authenticates successfully:

`60 + 20 = 80`

This allows the tool to distinguish between repeated failed authentication and suspicious activity that eventually results in a successful login.

## Successful Login Correlation

The detector can identify when a suspicious sequence of failed logins is followed by a successful login involving the same username and source IP.

Example:

```text
2026-09-29 10:00:01 FAILED_LOGIN user=admin src_ip=192.168.1.100
2026-09-29 10:00:08 FAILED_LOGIN user=admin src_ip=192.168.1.100
2026-09-29 10:00:15 FAILED_LOGIN user=admin src_ip=192.168.1.100
2026-09-29 10:00:22 FAILED_LOGIN user=admin src_ip=192.168.1.100
2026-09-29 10:00:29 FAILED_LOGIN user=admin src_ip=192.168.1.100
2026-09-29 10:01:02 SUCCESS_LOGIN user=admin src_ip=192.168.1.100
```

This activity produces:

* Severity: HIGH
* Attack Type: Possible Brute Force
* Successful Login: YES
* Risk Score: 80

## Usage

Run the detector using the default settings:

```bash
python failed_login_detector.py
```

Specify a custom input log:

```bash
python failed_login_detector.py --input test_auth.log
```

Specify an output CSV:

```bash
python failed_login_detector.py --input test_auth.log --output alerts.csv
```

Change the failed-login detection window:

```bash
python failed_login_detector.py --window 10
```

Change the minimum number of failed attempts required for an alert:

```bash
python failed_login_detector.py --threshold 5
```

Change the successful-login correlation window:

```bash
python failed_login_detector.py --success-window 1
```

Multiple options can be combined:

```bash
python failed_login_detector.py --input test_auth.log --output alerts.csv --window 10 --threshold 3 --success-window 5
```

## Command-Line Options

| Option | Default | Description |
|---|---
