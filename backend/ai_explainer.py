import requests
import os

def explain_attack(url, attack_type):

    # ✅ Handle safe URLs
    if not attack_type or attack_type.lower() in ["none", "safe"]:
        return "This URL does not contain any harmful or suspicious pattern."

    # ✅ Prompt
    prompt = f"""
Let me explain clearly why this URL is considered a {attack_type} attack.

Attack Type: {attack_type}
URL: {url}

1. Why this URL is dangerous:
Explain in 2 simple sentences. Clearly mention the suspicious part of the URL.

2. What could happen:
Explain in 2 simple sentences about the impact.

3. How to prevent it:
Give exactly 3 simple numbered steps.

Keep total answer under 150 words.
Do NOT add introduction.
Do NOT add conclusion.
Do NOT say things like "I hope this helps".
"""

    # ✅ Dynamic Ollama URL (works for local + EC2)
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": "tinyllama",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 250,
                    "temperature": 0.2
                }
            },
            timeout=30
        )

        # ✅ Success response
        if response.status_code == 200:
            data = response.json()
            return data.get("response", "No AI response.")

        # ❌ Ollama error
        else:
            return f"Ollama Error: {response.status_code} - {response.text}"

    # ⏱ Timeout handling
    except requests.exceptions.Timeout:
        return "AI explanation took too long. Try again."

    # 🌐 Connection error (VERY IMPORTANT for EC2 issues)
    except requests.exceptions.ConnectionError:
        return "Cannot connect to Ollama. Make sure it is running on EC2."

    # ❌ Generic error
    except Exception as e:
        return f"AI error: {str(e)}"