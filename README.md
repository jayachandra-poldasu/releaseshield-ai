# ReleaseShield AI 🛡️

An AI-powered pre-deployment risk engine designed to prevent production outages by analyzing the blast radius of infrastructure changes.

## 🏗️ Architecture

```mermaid
graph TD
    A[Engineer/CI-CD] -->|Uploads JSON Plan| B[Streamlit UI]
    B -->|Post Request| C[FastAPI Backend]
    C -->|Lookup| D[(Service Map JSON)]
    C -->|Lookup| E[(Incident History JSON)]
    C -->|Scoring Logic| F[Risk Engine]
    F -->|Context + Score| G[Local LLM - Ollama]
    G -->|Reasoning| B
    B -->|Safety Verdict| A