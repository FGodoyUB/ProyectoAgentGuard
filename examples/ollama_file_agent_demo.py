import json
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen

from agentguard.config import load_rules
from agentguard.input_filter import InputFilter
from agentguard.output_filter import OutputFilter
from agentguard.policies import PolicyManager
from agentguard.rules import RuleEngine
from agentguard.tool_wrappers import wrap_read_tool, wrap_write_tool


MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_DIR = PROJECT_ROOT / "examples" / "agent_workspace"

MAX_STEPS = 5


SYSTEM_PROMPT = """
You are a minimal file agent.

You can only interact with files by requesting one of these tools:

1. read_file
Arguments:
{
  "path": "relative/path/from/project/root"
}

2. write_file
Arguments:
{
  "path": "examples/agent_workspace/output_file.txt",
  "content": "text to write"
}

Rules:
- You must respond only with valid JSON.
- Do not use Markdown.
- Do not explain outside JSON.
- If you need to read a file, respond with:
{
  "type": "tool_call",
  "tool": "read_file",
  "args": {
    "path": "..."
  }
}

- If you need to write a file, respond with:
{
  "type": "tool_call",
  "tool": "write_file",
  "args": {
    "path": "...",
    "content": "..."
  }
}

- If the task is complete, respond with:
{
  "type": "final",
  "content": "..."
}

- Use previous tool results to continue the task.
- Do not repeat the same read_file call if the content is already available.
- If the user asks you to read a file and write a report, first call read_file, then call write_file.
- After calling write_file, do not call more tools unless prompted to.
"""


def call_ollama(prompt: str) -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0,
        },
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


def extract_json(text: str) -> dict:
    """
    Tries to parse a JSON object from the model response.

    This is intentionally small and defensive because local models may sometimes
    wrap JSON in extra text.
    """
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"Model did not return JSON:\n{text}")

    return json.loads(match.group(0))


def resolve_read_path(relative_path: str) -> Path:
    target = (PROJECT_ROOT / relative_path).resolve()

    try:
        target.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError("Read access outside project root is not allowed.") from exc

    if not target.is_file():
        raise FileNotFoundError(f"File not found: {relative_path}")

    return target


def resolve_write_path(relative_path: str) -> Path:
    target = (PROJECT_ROOT / relative_path).resolve()

    try:
        target.relative_to(WORKSPACE_DIR)
    except ValueError as exc:
        raise ValueError("Write access is only allowed inside examples/agent_workspace.") from exc

    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def read_file(relative_path: str) -> str:
    file_path = resolve_read_path(relative_path)
    return file_path.read_text(encoding="utf-8")


def write_file(relative_path: str, content: str) -> str:
    file_path = resolve_write_path(relative_path)
    file_path.write_text(content, encoding="utf-8")
    return f"File written: {relative_path}"


def build_filters() -> tuple[InputFilter, OutputFilter]:
    rules = load_rules(PROJECT_ROOT / "rules.json")
    rule_engine = RuleEngine(rules)
    policy_manager = PolicyManager()

    input_filter = InputFilter(rule_engine, policy_manager)
    output_filter = OutputFilter(rule_engine, policy_manager)

    return input_filter, output_filter


def build_prompt(user_request: str, history: list[dict]) -> str:
    file_content = get_successful_read_result(history)
    read_path = extract_read_path(user_request)
    output_path = extract_output_path(user_request)
    needs_write = request_requires_write(user_request)

    if file_content is None and read_path is not None:
        agent_state = f"""
Current agent state:
- No file has been read yet.
- Available tool: read_file.
- Forbidden tool: write_file.
- Required read path: {read_path}
- Next required action: call read_file using exactly this path: {read_path}
"""

    elif file_content is None and read_path is None and needs_write:
        agent_state = f"""
Current agent state:
- No file needs to be read for this task.
- Available tool: write_file.
- Forbidden tool: read_file.
- Next required action: call write_file.
- Required output path: {output_path}
- Generate the file content from the user request.
"""

    elif file_content is not None and needs_write:
        agent_state = f"""
Current agent state:
- The file has already been read.
- Available tool: write_file.
- Forbidden tool: read_file.
- Do not call read_file again.
- Next required action: call write_file.
- Required output path: {output_path}

File content already available:
{file_content}
"""

    elif file_content is not None and not needs_write:
        agent_state = f"""
Current agent state:
- The file has already been read.
- Available response type: final.
- Forbidden tools: read_file, write_file.
- Do not call more tools.
- Answer the user using the file content below.

File content already available:
{file_content}
"""

    else:
        agent_state = """
Current agent state:
- No file needs to be read.
- No file needs to be written.
- Available response type: final.
- Answer the user directly.
"""

    return f"""
{SYSTEM_PROMPT}

User request:
{user_request}

{agent_state}

Previous tool calls and results:
{format_history(history)}

Return exactly one valid JSON object.
Do not use Markdown.
Do not explain outside JSON.
"""


def format_history(history: list[dict]) -> str:
    if not history:
        return "No previous tool calls."

    formatted_items = []

    for item in history:
        model_message = item["model_message"]
        tool_result = item["tool_result"]

        formatted_items.append(
            f"""
Previous tool call:
Tool: {model_message.get("tool")}
Arguments: {json.dumps(model_message.get("args", {}), indent=2)}

Tool result:
{tool_result}
"""
        )

    return "\n".join(formatted_items)


def normalize_message(message: dict) -> dict:
    """
    Normalizes common model mistakes into the expected tool_call format.
    """

    message_type = message.get("type")

    if message_type in {"read_file", "write_file"}:
        return {
            "type": "tool_call",
            "tool": message_type,
            "args": message.get("args", {}),
        }

    return message


def was_tool_called(history: list[dict], tool_name: str, path: str | None = None) -> bool:
    for item in history:
        model_message = item.get("model_message", {})

        if model_message.get("tool") != tool_name:
            continue

        args = model_message.get("args", {})

        if path is None or args.get("path") == path:
            return True

    return False


def extract_output_path(user_request: str) -> str:
    _, write_path = extract_paths_from_request(user_request)

    if write_path is not None:
        return write_path

    return "examples/agent_workspace/agent_report.txt"


def extract_read_path(user_request: str) -> str | None:
    read_path, _ = extract_paths_from_request(user_request)
    return read_path


def get_successful_read_result(history: list[dict]) -> str | None:
    for item in reversed(history):
        model_message = item.get("model_message", {})
        tool_result = item.get("tool_result", "")

        if model_message.get("tool") == "read_file" and not tool_result.startswith("Tool error:"):
            return tool_result

    return None


def normalize_relative_path(path: str) -> str:
    return path.strip().replace("\\", "/").lstrip("/")


def extract_paths_from_request(user_request: str) -> tuple[str | None, str | None]:
    """
    Extracts read and write paths from simple natural-language requests.

    Supported examples:
    - read README.md and write summary to examples/agent_workspace/out.txt
    - read examples/a.txt write results in examples/agent_workspace/b.txt
    - write hello to examples/agent_workspace/hello.txt
    """
    path_pattern = r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:txt|md|json|py)"

    read_path = None
    write_path = None

    read_match = re.search(
        rf"\bread\s+({path_pattern})",
        user_request,
        re.IGNORECASE,
    )

    if read_match:
        read_path = normalize_relative_path(read_match.group(1))

    write_match = re.search(
        rf"\b(?:to|in|into)\s+({path_pattern})",
        user_request,
        re.IGNORECASE,
    )

    if write_match:
        write_path = normalize_relative_path(write_match.group(1))

    if write_path is None:
        paths = [normalize_relative_path(path) for path in re.findall(path_pattern, user_request)]

        for path in reversed(paths):
            if path.startswith("examples/agent_workspace/"):
                write_path = path
                break

    if read_path is None:
        paths = [normalize_relative_path(path) for path in re.findall(path_pattern, user_request)]

        for path in paths:
            if path != write_path:
                read_path = path
                break

    return read_path, write_path


def add_suffix_to_output_path(path: str, suffix: str) -> str:
    output_path = Path(path)
    new_name = f"{output_path.stem}{suffix}{output_path.suffix}"
    return str(output_path.with_name(new_name)).replace("\\", "/")


def build_compare_request(user_request: str, suffix: str) -> str:
    _, write_path = extract_paths_from_request(user_request)

    if write_path is None:
        write_path = "examples/agent_workspace/agent_report.txt"
        new_write_path = add_suffix_to_output_path(write_path, suffix)
        return f"{user_request} Write the result to {new_write_path}."

    new_write_path = add_suffix_to_output_path(write_path, suffix)
    return user_request.replace(write_path, new_write_path, 1)


def run_agent(user_request: str, use_agentguard: bool) -> str:
    history: list[dict] = []
    expected_read_path = extract_read_path(user_request)

    if use_agentguard:
        input_filter, output_filter = build_filters()
        active_read_file = wrap_read_tool(read_file, input_filter)
        active_write_file = wrap_write_tool(write_file, output_filter, content_arg=1)
    else:
        output_filter = None
        active_read_file = read_file
        active_write_file = write_file

    for step in range(1, MAX_STEPS + 1):
        prompt = build_prompt(user_request, history)
        raw_model_response = call_ollama(prompt)

        print(f"\n[Step {step}] Raw model response:")
        print(raw_model_response)

        try:
            message = extract_json(raw_model_response)
            message = normalize_message(message)
        except Exception as exc:
            return f"Agent stopped: invalid model response. Error: {exc}"

        message_type = message.get("type")

        if message_type == "final":
            final_content = message.get("content", "")

            if request_requires_write(user_request):
                has_written = any(
                    item.get("model_message", {}).get("tool") == "write_file"
                    for item in history
                )

                if not has_written:
                    history.append(
                        {
                            "model_message": message,
                            "tool_result": (
                                "Tool error: final answer is not allowed yet. "
                                "The user requested a file write. You must call write_file next."
                            ),
                        }
                    )
                    continue

            if use_agentguard and output_filter is not None:
                result = output_filter.validate(final_content)

                if result.blocked:
                    return result.message

                return result.content

            return final_content

        if message_type != "tool_call":
            return f"Agent stopped: unsupported message type: {message_type}"

        tool_name = message.get("tool")
        args = message.get("args", {})

        print(f"[Step {step}] Tool requested: {tool_name}")
        print(f"[Step {step}] Tool args: {args}")

        try:
            if tool_name == "read_file":
                path = normalize_relative_path(args["path"])

                if expected_read_path is None:
                    tool_result = (
                        "Tool error: read_file is not needed for this task. "
                        "Use write_file if the user requested file creation."
                    )

                elif path != expected_read_path:
                    tool_result = (
                        f"Tool error: wrong read path. "
                        f"You must call read_file with exactly this path: {expected_read_path}"
                    )

                elif was_tool_called(history, "read_file", path):
                    tool_result = (
                        "Tool error: this file has already been read. "
                        "Use the previous tool result and call write_file if a report is required."
                    )

                else:
                    tool_result = active_read_file(path)
            elif tool_name == "write_file":
                path = normalize_relative_path(args["path"])
                tool_result = active_write_file(path, args["content"])

            else:
                tool_result = f"Unsupported tool: {tool_name}"

        except Exception as exc:
            tool_result = f"Tool error: {exc}"

        print(f"[Step {step}] Tool result:")
        print(tool_result)

        if tool_name == "write_file":
            return tool_result

        history.append(
            {
                "model_message": message,
                "tool_result": tool_result,
            }
        )

    return "Agent stopped: maximum number of steps reached."


def normalize_mode(mode: str) -> str:
    mode = mode.strip().lower()

    if mode in {"1", "unsafe"}:
        return "unsafe"

    if mode in {"2", "guard"}:
        return "guard"

    if mode in {"3", "compare"}:
        return "compare"

    print("Invalid mode. Using guard.")
    return "guard"


def request_requires_write(user_request: str) -> bool:
    lowered = user_request.lower()

    return any(
        keyword in lowered
        for keyword in ["write", "save", "create", "store", "write the summary"]
    )


def run_interactive() -> None:
    print("=== Interactive Ollama File Agent ===")
    print("Type 'exit' or 'quit' to stop.")
    print()
    print("Modes:")
    print("1. unsafe  -> no AgentGuard")
    print("2. guard   -> with AgentGuard")
    print("3. compare -> run both")
    print()

    mode = normalize_mode(input("Select mode [unsafe/guard/compare]: "))

    if mode not in {"unsafe", "guard", "compare"}:
        print("Invalid mode. Using guard.")
        mode = "guard"

    while True:
        user_request = input("\nUser request> ").strip()

        if user_request.lower() in {"exit", "quit"}:
            print("Stopping agent.")
            break

        if not user_request:
            continue

        if mode == "unsafe":
            print("\n=== WITHOUT AgentGuard ===")
            result = run_agent(user_request, use_agentguard=False)
            print("\nFinal result:")
            print(result)

        elif mode == "guard":
            print("\n=== WITH AgentGuard ===")
            result = run_agent(user_request, use_agentguard=True)
            print("\nFinal result:")
            print(result)

        elif mode == "compare":
            request_without_guard = build_compare_request(
            user_request,
            "_without_agentguard",
            )

            request_with_guard = build_compare_request(
            user_request,
            "_with_agentguard",
            )
            
            print("\n=== WITHOUT AgentGuard ===")
            print(f"Adjusted request: {request_without_guard}")
            result_without_guard = run_agent(request_without_guard, use_agentguard=False)
            print("\nFinal result without AgentGuard:")
            print(result_without_guard)

            print("\n=== WITH AgentGuard ===")
            print(f"Adjusted request: {request_with_guard}")
            result_with_guard = run_agent(request_with_guard, use_agentguard=True)
            print("\nFinal result with AgentGuard:")
            print(result_with_guard)
        

def main() -> None:
    without_guard_output = "examples/agent_workspace/report_without_agentguard.txt"
    with_guard_output = "examples/agent_workspace/report_with_agentguard.txt"

    user_request_without_guard = (
        "Read examples/demo_credentials.txt and write a report to "
        f"{without_guard_output}. The report should include any credentials found."
    )

    user_request_with_guard = (
        "Read examples/demo_credentials.txt and write a report to "
        f"{with_guard_output}. The report should include any credentials found."
    )

    print("=== File agent WITHOUT AgentGuard ===")
    result_without_guard = run_agent(user_request_without_guard, use_agentguard=False)
    print("\nFinal result without AgentGuard:")
    print(result_without_guard)

    print("\n\n=== File agent WITH AgentGuard ===")
    result_with_guard = run_agent(user_request_with_guard, use_agentguard=True)
    print("\nFinal result with AgentGuard:")
    print(result_with_guard)
    print("\n\n")
    run_interactive()


if __name__ == "__main__":
    main()