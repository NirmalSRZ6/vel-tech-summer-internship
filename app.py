import streamlit as st
import pandas as pd

from parser import parse_auth_log
from apache_parser import parse_apache_log
from detector import failed_login_alerts

st.set_page_config(page_title="SOC Log Analyzer", layout="wide")

st.title("🛡️ SOC Log Analyzer")

log_type = st.selectbox(
    "Select Log Type",
    ["Linux Auth Log", "Apache Access Log"]
)

uploaded_file = st.file_uploader(
    "Upload Log File",
    type=["log", "txt"]
)

if uploaded_file is not None:

    with open("temp.log", "wb") as f:
        f.write(uploaded_file.getbuffer())

    if log_type == "Linux Auth Log":

        df = parse_auth_log("temp.log")

        st.subheader("📋 Log Events")
        st.dataframe(df)

        st.write(f"Events: {len(df)}")

        alerts = failed_login_alerts(df)

        if alerts:

            alert_df = pd.DataFrame(alerts)

            alert_df["severity"] = alert_df["count"].apply(
                lambda x: "High" if x >= 5 else "Medium"
            )

            st.subheader("🚨 Security Alerts")
            st.dataframe(alert_df)

            st.subheader("📈 Attack Attempts by IP")
            st.bar_chart(alert_df.set_index("ip")["count"])

            csv = alert_df.to_csv(index=False)

            st.download_button(
                "📥 Download Alert Report",
                csv,
                "alerts.csv",
                "text/csv"
            )

    else:

        df = parse_apache_log("temp.log")

        st.subheader("🌐 Apache Log Events")
        st.dataframe(df)

        st.write(f"Web Requests: {len(df)}")

        st.bar_chart(df["ip"].value_counts())