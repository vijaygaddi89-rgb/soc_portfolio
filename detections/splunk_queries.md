# SOC Detection Queries — Splunk SPL

## 1. SSH Brute Force Detection
```
index=main sourcetype=auth_log "Invalid user"
| stats count by host
| where count > 5
| sort -count
```

## 2. Directory Scanning Detection
```
index=main sourcetype=apache_access_log
| rex field=_raw "^(?P<clientip>\S+).*\"(?P<status>\d+)"
| where status="404"
| stats count by clientip
| where count > 10
| sort -count
```

## 3. Port Scan Detection
```
index=main sourcetype=auth_log
"Unable to negotiate"
| stats count by host
| sort -count
```

## 4. Events Timeline
```
index=main
| timechart count by sourcetype span=1h
```

## 5. Top Attacking IPs Across All Logs
```
index=main sourcetype=auth_log "Invalid user"
| stats count by host
| sort -count
| head 10
```
