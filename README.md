# 🔍 Splunk Investigation 1 — Joomla Brute Force Attack Analysis

> **Blue Team Lab** | BOTSv1 Dataset | Splunk Enterprise  
> Tools: Splunk SIEM · SPL · stream:http · BOTSv1

---

## 📋 Overview

This investigation uses the **Splunk Boss of the SOC v1 (BOTSv1)** dataset to analyse a real-world brute force attack targeting a Joomla CMS administrator login page hosted at `imreallynotbatman.com`.

The lab demonstrates core SOC analyst skills including:
- Threat detection via SPL queries
- Source IP identification
- Attack pattern analysis
- Form data extraction
- Dashboard creation

---

## 🧰 Environment Setup

### Prerequisites
- Splunk Enterprise (v10.x)
- BOTSv1 Attack-Only Dataset

### Dataset Installation

```bash
# Download BOTSv1 attack-only dataset
wget https://s3.amazonaws.com/botsdataset/botsv1/botsv1-attack-only.tgz

# Extract to temp location
tar -xvzf botsv1-attack-only.tgz -C /tmp/

# Copy app to Splunk
cp -r /tmp/botsv1_data_set /opt/splunk/etc/apps/

# Move pre-indexed data to correct Splunk DB location
mv /tmp/botsv1_data_set/var/lib/splunk/botsv1 /opt/splunk/var/lib/splunk/botsv1
```

### Fix indexes.conf

Edit `/opt/splunk/etc/apps/botsv1_data_set/default/indexes.conf`:

```ini
[botsv1]
homePath   = $SPLUNK_DB/botsv1/db
coldPath   = $SPLUNK_DB/botsv1/colddb
thawedPath = $SPLUNK_DB/botsv1/thaweddb
disabled = false
frozenTimePeriodInSecs = 377395200
```

```bash
# Fix ownership and restart
chown -R ubuntu:ubuntu /opt/splunk/etc/apps/botsv1_data_set
chown -R ubuntu:ubuntu /opt/splunk/var/lib/splunk/botsv1
/opt/splunk/bin/splunk restart
```

---

## 🔎 Investigation Questions & SPL Queries

### Question 1 — Identify Malicious Activity

**Q:** How many POST events were made to the Joomla admin login page?

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php"
```

**Answer:** `425 events`

---

### Question 2 — Identify Source IP

**Q:** Which source IP is responsible for the majority of the traffic?

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php"
| stats count by src_ip
```

**Answer:** `23.22.63.114` (412 out of 425 events = 97%)

---

### Question 3 — Filter by Attacker IP

**Q:** After filtering by the attacker IP, how many events remain?

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php" src_ip="23.22.63.114"
```

**Answer:** `412 events`

---

### Question 4 — Identify Destination IP (Web Server)

**Q:** What is the IP address of the web server hosting `imreallynotbatman.com`?

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php"
| stats count by dest_ip
```

**Answer:** `192.168.250.70`

---

### Question 5 — Extract Username from Form Data

**Q:** What username is the attacker trying to use at timestamp `2016-08-10T21:46:44.453730Z`?

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php" src_ip="23.22.63.114"
| spath timestamp
| search timestamp="2016-08-10T21:46:44.453730Z"
```

Look at the `form_data` field — value before first `&`:

**Answer:** `username=admin`

---

### Question 6 — Extract Password from Form Data

**Q:** What password is being entered in the same event?

From the same `form_data` field, extract `passwd` value before `&`:

**Answer:** `passwd=baby` (from `passwd=baby&26a9247d...`)

---

### Question 7 — First Password in Brute Force Attack

**Q:** What was the very first password attempted in the brute force attack?

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php" src_ip="23.22.63.114"
| table timestamp, form_data
```

Sort by `timestamp` ascending (oldest first).

**Answer:** `passwd=12345678` (from the earliest event at `2016-08-10T21:45:10.253339Z`)

---

## 📊 Dashboard

A Splunk dashboard was created with the following panels:

| Panel | Query | Visualization |
|---|---|---|
| Total Brute Force Attempts | `... \| stats count` | Single Value |
| Attacks Over Time | `... \| timechart count` | Line Chart |
| Top Source IPs | `... \| stats count by src_ip` | Bar Chart |
| Top Destination IPs | `... \| stats count by dest_ip` | Bar Chart |

---

## 🧠 Key Findings

| Field | Value |
|---|---|
| Attack Type | HTTP Brute Force |
| Target | Joomla Admin Login (`/joomla/administrator/index.php`) |
| Attacker IP | `23.22.63.114` |
| Target Server IP | `192.168.250.70` |
| Target Domain | `imreallynotbatman.com` |
| Total Attack Events | 412 |
| Username Attempted | `admin` |
| Attack Timeframe | August 2016 |

---

## 🛡️ MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Repeated login attempts to Joomla admin panel |
| Valid Accounts | T1078 | Attempting to gain access using `admin` account |
| Exploit Public-Facing Application | T1190 | Targeting Joomla CMS |

---

## 📁 Repo Structure

```
splunk-investigation-1/
├── README.md               # This file
├── queries/
│   └── investigation1.spl  # All SPL queries used
├── screenshots/            # Evidence screenshots
└── setup/
    └── indexes.conf        # Correct indexes.conf for BOTSv1
```

---

## 👤 Author

**Ankit P.** | [LinkedIn](https://www.linkedin.com/in/ankitp26)  
Master of Cybersecurity — Holmes Institute  
CAPT Certified | SOC Analyst

---

## 📜 Disclaimer

This investigation uses the publicly available BOTSv1 dataset released by Splunk for educational purposes. All findings are based on simulated/historical attack data.
