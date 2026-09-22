import json
import os
from urllib.request import Request, urlopen


MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def call_ollama(prompt: str) -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    }

    request = Request(
        url=f"{OLLAMA_BASE_URL}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(request, timeout=120) as response:
        data = json.loads(response.read().decode("utf-8"))

    return data["response"]


def main() -> None:
    response = call_ollama("Respondé solamente OK2.")
    print(response)


if __name__ == "__main__":
    main()