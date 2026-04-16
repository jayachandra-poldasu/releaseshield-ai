from fastapi import FastAPI
import json
import requests

app = FastAPI()

# Load Data
with open("data/service_map.json") as f:
    SERVICE_MAP = json.load(f)
with open("data/incident_history.json") as f:
    INCIDENTS = json.load(f)

@app.post("/analyze")
def analyze_risk(plan: dict):
    resource = plan.get("resource")
    action = plan.get("action") # 'update' or 'delete'

    # 1. Base Score
    score = 40 if action == "delete" else 15
    
    # 2. Blast Radius Calculation
    impacted = [s for s, info in SERVICE_MAP.items() if resource in info["dependencies"]]
    score += (len(impacted) * 20)

    # 3. AI Insight from your local M1 (Ollama)
    prompt = f"As an SRE Lead, analyze this: Resource {resource} is being {action}d. Risk Score: {score}. Impacted: {impacted}. Give a 1-sentence warning."
    
    try:
        # We use llama3 because you just pulled it!
        response = requests.post("http://localhost:11434/api/generate", 
                                 json={"model": "llama3", "prompt": prompt, "stream": False})
        ai_advice = response.json().get("response")
    except:
        ai_advice = "AI analysis offline. Proceed with manual check."

    return {
        "score": score,
        "impacted": impacted,
        "recommendation": "HOLD" if score > 60 else "CANARY",
        "ai_summary": ai_advice
    }