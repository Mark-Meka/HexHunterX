import asyncio
import yaml
import requests

# Quick script to test the OpenRouter AI connection
from ai.client import _build_headers, _build_payload, OPENROUTER_URL

def main():
    with open("config/default.yaml", "r") as f:
        config = yaml.safe_load(f)
        
    api_key = config.get("ai", {}).get("api_key")
    model = config.get("ai", {}).get("model", "google/gemma-2-9b-it:free")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://github.com/Mark-Meka/HexHunterX",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": "Say hello"}
        ]
    }
    
    print(f"Testing Model: {model}")
    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
