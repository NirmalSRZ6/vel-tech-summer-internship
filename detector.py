
def failed_login_alerts(df, threshold=3):
    if df.empty: return []
    counts=df[df["event"]=="Failed"]["ip"].value_counts()
    return [{"ip":ip,"type":"Brute Force","count":c} for ip,c in counts.items() if c>=threshold]
