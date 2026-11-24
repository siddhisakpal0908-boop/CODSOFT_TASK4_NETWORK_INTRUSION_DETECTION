
import json
from pathlib import Path
from collections import Counter

eve_file = Path("logs/eve.json")
report_file = Path("logs/response_report.txt")

alert_counts = Counter()
alert_details = []

if not eve_file.exists():
    print("Suricata log file not found.")
    raise SystemExit

with eve_file.open("r", encoding="utf-8") as file:
    for line in file:
        try:
            event = json.loads(line)

            if event.get("event_type") == "alert":
                alert = event.get("alert", {})
                signature = alert.get("signature", "Unknown")
                source_ip = event.get("src_ip", "Unknown")

                alert_counts[signature] += 1

                alert_details.append({
                    "signature": signature,
                    "source_ip": source_ip,
                    "timestamp": event.get("timestamp", "")
                })

        except json.JSONDecodeError:
            continue

with report_file.open("w", encoding="utf-8") as report:
    report.write("NIDS SECURITY RESPONSE SUMMARY\n")
    report.write("=" * 40 + "\n")

    for signature, count in alert_counts.items():
        report.write(f"{signature}: {count}\n")

    report.write(f"\nTotal alerts: {sum(alert_counts.values())}\n")
    report.write("\nRESPONSE: All alerts recorded for investigation.\n")

print("\nNIDS SECURITY RESPONSE SUMMARY")
print("=" * 40)

for signature, count in alert_counts.items():
    print(f"{signature}: {count}")

print("\nTotal alerts:", sum(alert_counts.values()))
print("Report saved to:", report_file)
