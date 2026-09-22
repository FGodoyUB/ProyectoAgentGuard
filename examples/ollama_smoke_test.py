import os

import ollama


MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")


def main() -> None:
    client = ollama.Client(host=OLLAMA_HOST)

    response = client.generate(
        model=MODEL,
        prompt="Respondé en una sola oración qué es un agente LLM.",
    )

    print(response["response"])


if __name__ == "__main__":
    main()