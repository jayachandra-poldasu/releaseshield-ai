import streamlit as st
import requests
import json

st.set_page_config(page_title="ReleaseShield AI", layout="wide", page_icon="🛡️")

st.title("🛡️ ReleaseShield AI: Enterprise Risk Engine")
st.markdown("---")

# Sidebar for instructions
with st.sidebar:
    st.header("Instructions")
    st.write("1. Upload a JSON change-set.")
    st.write("2. The engine analyzes dependencies.")
    st.write("3. AI provides a safety verdict.")

# File Uploader
uploaded_file = st.file_uploader("Upload Infrastructure Change-set (JSON)", type=['json'])

if uploaded_file is not None:
    # Read the file
    plan_data = json.load(uploaded_file)
    st.json(plan_data) # Show the user what they uploaded

    if st.button("Analyze Release"):
        with st.spinner("🤖 Consulting Local LLM and checking blast radius..."):
            # Send the whole JSON to the backend
            try:
                res = requests.post("http://localhost:8000/analyze", json=plan_data).json()
                
                # Results UI
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Risk Score", res["score"])
                    st.subheader(f"Verdict: {res['recommendation']}")
                    st.write("**Impacted Services:**")
                    for svc in res["impacted"]:
                        st.write(f"- `{svc}`")
                
                with col2:
                    st.info("**AI SRE Assistant Analysis**")
                    st.write(res["ai_summary"])
            except Exception as e:
                st.error(f"Connection Error: Is the FastAPI server running? ({e})")