
import pandas as pd, re

def parse_auth_log(path):
    rows=[]
    with open(path) as f:
        for line in f:
            m=re.search(r'(Failed|Accepted) password .* from ([0-9.]+)', line)
            if m:
                rows.append({"event":m.group(1),"ip":m.group(2)})
    return pd.DataFrame(rows)

def parse_apache_log(path):
    rows=[]
    with open(path) as f:
        for line in f:
            m=re.search(r'([0-9.]+).*\"\S+ (\S+) .*" (\d+)', line)
            if m:
                rows.append({"ip":m.group(1),"url":m.group(2),"status":int(m.group(3))})
    return pd.DataFrame(rows)
