from collections.abc import Callable
from typing import Any

from agentguard.models import FilterResult


BLOCKED_READ_MESSAGE = (
    "[BLOCKED_BY_AGENTGUARD] External content was blocked by security policy."
)

BLOCKED_WRITE_MESSAGE = (
    "[BLOCKED_BY_AGENTGUARD] Output was blocked by security policy."
)


def secure_read_text(text: str, input_filter) -> FilterResult:
    """
    Validate externally read text before it is passed to an agent.
    """
    return input_filter.validate(text)


def secure_write_text(text: str, output_filter) -> FilterResult:
    """
    Validate output text before it is written, sent, or exposed.
    """
    return output_filter.validate(text)


def wrap_read_tool(tool_func: Callable[..., Any], input_filter) -> Callable[..., str]:
    """
    Wrap a read-like tool.

    The wrapped tool executes the original function, converts its result to text,
    validates it with the input filter, and returns safe content.
    """

    def wrapped(*args: Any, **kwargs: Any) -> str:
        raw_content = tool_func(*args, **kwargs)
        result = input_filter.validate(str(raw_content))

        if result.blocked:
            return BLOCKED_READ_MESSAGE

        return result.content

    return wrapped


def wrap_write_tool(
    tool_func: Callable[..., Any],
    output_filter,
    content_arg: int | str = 0,
) -> Callable[..., Any]:
    """
    Wrap a write-like tool.

    By default, the content to validate is expected as the first positional argument.
    For functions like write_file(path, content), use content_arg=1.
    For keyword-based tools, use content_arg="content".
    """

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        args_list = list(args)

        if isinstance(content_arg, int):
            if content_arg >= len(args_list):
                raise IndexError("content_arg index is out of range")

            original_content = args_list[content_arg]
        else:
            if content_arg not in kwargs:
                raise KeyError(f"content_arg '{content_arg}' was not found in kwargs")

            original_content = kwargs[content_arg]

        result = output_filter.validate(str(original_content))

        if result.blocked:
            return BLOCKED_WRITE_MESSAGE

        if isinstance(content_arg, int):
            args_list[content_arg] = result.content
        else:
            kwargs[content_arg] = result.content

        return tool_func(*args_list, **kwargs)

    return wrapped