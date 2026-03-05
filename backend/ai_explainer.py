import requests

def explain_attack(url, attack_type):

    if not attack_type or attack_type.lower() in ["none", "safe"]:
        return "This URL does not contain any harmful or suspicious pattern."

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

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "tinyllama",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 250,   # smaller = no cutoff
                    "temperature": 0.2
                }
            },
            timeout=30
        )

        if response.status_code == 200:
            return response.json().get("response", "No AI response.")
        else:
            return f"Ollama Error: {response.status_code}"

    except requests.exceptions.Timeout:
        return "AI explanation took too long. Try again."
    except Exception as e:
        return f"Local AI error: {str(e)}"