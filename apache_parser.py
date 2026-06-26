import pandas as pd
import re

def parse_apache_log(file_path):
    events = []

    with open(file_path, "r") as f:
        for line in f:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)

            if ip_match:
                events.append({
                    "ip": ip_match.group(1),
                    "event": "Web Request"
                })

    return pd.DataFrame(events)