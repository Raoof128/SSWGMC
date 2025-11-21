from __future__ import annotations

"""Streamlit dashboard for observing Secure Web Gateway activity."""

import json
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st

LOG_PATH = Path("streamlit_logs/gateway.log")


st.set_page_config(page_title="SASE Gateway Dashboard", layout="wide")
st.title("SASE / Secure Web Gateway Dashboard")


def load_logs() -> List[dict]:
    if not LOG_PATH.exists():
        return []
    with LOG_PATH.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def render_summary(logs: List[dict]) -> None:
    st.subheader("Traffic Summary")
    if not logs:
        st.info("No traffic recorded yet.")
        return
    df = pd.DataFrame(logs)
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", len(df))
    blocked = df[~df["allowed"]]
    col2.metric("Blocked", len(blocked))
    col3.metric("Unique Users", df["user"].nunique())

    st.markdown("### Top Domains")
    st.bar_chart(df["domain"].value_counts().head(10))

    st.markdown("### Category Distribution")
    exploded = df.explode("categories")
    st.bar_chart(exploded["categories"].value_counts().head(10))

    st.markdown("### DLP / CASB Insights")
    findings = df["dlp_findings"].replace("", float("nan")).dropna()
    casb_apps = df["casb"].apply(lambda item: item.get("app"))
    col4, col5 = st.columns(2)
    col4.metric("DLP Findings", len(findings))
    col5.metric("CASB App Matches", casb_apps.notna().sum())


logs = load_logs()
render_summary(logs)

if logs:
    st.subheader("Recent Events")
    st.dataframe(pd.DataFrame(logs).tail(50))
