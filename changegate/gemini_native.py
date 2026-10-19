"""A native google-genai chat model for Gemini 3.x, used instead of langchain-google-genai.

langchain-google-genai 2.1.12 does not preserve Gemini's ``thought_signature`` on function call parts
across turns. Gemini 3 models require it: resending a function call without its original
``thought_signature`` fails with "400 Function call is missing a thought_signature in functionCall
parts" on the second tool call of a run (confirmed against gemini-3.8-flash). This wrapper stores the
raw response parts, thought_signature included, in ``AIMessage.additional_kwargs["gemini_parts"]`` and
replays them verbatim on the next turn instead of re-deriving the request from the LangChain tool_calls
schema, which drops that field.
"""

from __future__ import annotations

import time
from typing import Any, Sequence

from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import PrivateAttr


def _tool_message_name(message: ToolMessage) -> str:
    return message.name or message.additional_kwargs.get("name", "")


class ChatGeminiNative(BaseChatModel):
    """Minimal tool-calling chat model over the google-genai SDK, Gemini 3 thought_signature safe."""

    model: str
    api_key: str
    temperature: float = 0.0
    timeout_s: int = 300

    _client: Any = PrivateAttr(default=None)
    _tools: list | None = PrivateAttr(default=None)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._client = genai.Client(api_key=self.api_key)

    @property
    def _llm_type(self) -> str:
        return "gemini-native"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"model": self.model, "temperature": self.temperature}

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> "ChatGeminiNative":
        declarations = []
        for tool in tools:
            spec = convert_to_openai_tool(tool)["function"]
            declarations.append(
                types.FunctionDeclaration(
                    name=spec["name"],
                    description=spec.get("description", ""),
                    parameters_json_schema=spec.get("parameters") or {"type": "object", "properties": {}},
                )
            )
        clone = self.model_copy()
        clone._client = self._client
        clone._tools = [types.Tool(function_declarations=declarations)]
        return clone

    def _to_contents(self, messages: list[BaseMessage]) -> tuple[str | None, list[types.Content]]:
        system_text: str | None = None
        contents: list[types.Content] = []
        for message in messages:
            if isinstance(message, SystemMessage):
                text = str(message.content)
                system_text = f"{system_text}\n\n{text}" if system_text else text
            elif isinstance(message, HumanMessage):
                contents.append(types.Content(role="user", parts=[types.Part.from_text(text=str(message.content or ""))]))
            elif isinstance(message, AIMessage):
                raw = message.additional_kwargs.get("gemini_parts")
                if raw:
                    contents.append(types.Content(role="model", parts=[types.Part.model_validate(p) for p in raw]))
                    continue
                # No stored raw parts (for example a plain AIMessage inserted for a nudge): rebuild from the
                # LangChain fields. This loses thought_signature, so it only happens for messages this model
                # itself did not produce.
                parts = []
                if message.content:
                    parts.append(types.Part.from_text(text=str(message.content)))
                for call in message.tool_calls or []:
                    parts.append(types.Part.from_function_call(name=call["name"], args=call["args"]))
                contents.append(types.Content(role="model", parts=parts or [types.Part.from_text(text="")]))
            elif isinstance(message, ToolMessage):
                response_part = types.Part(
                    function_response=types.FunctionResponse(
                        id=message.tool_call_id,
                        name=_tool_message_name(message),
                        response={"result": message.content},
                    )
                )
                contents.append(types.Content(role="user", parts=[response_part]))
        return system_text, contents

    def _call_with_retry(self, contents: list[types.Content], config: types.GenerateContentConfig, attempts: int = 5):
        delay = 5.0
        for attempt in range(attempts):
            try:
                return self._client.models.generate_content(model=self.model, contents=contents, config=config)
            except genai_errors.ServerError:
                if attempt == attempts - 1:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 60.0)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        system_text, contents = self._to_contents(messages)
        config = types.GenerateContentConfig(
            temperature=self.temperature,
            tools=self._tools,
            system_instruction=system_text,
        )
        response = self._call_with_retry(contents, config)
        candidate = response.candidates[0]
        parts = candidate.content.parts or []
        text = "".join(part.text or "" for part in parts if part.text)
        tool_calls = []
        for i, part in enumerate(parts):
            if part.function_call:
                tool_calls.append(
                    {
                        "name": part.function_call.name,
                        "args": dict(part.function_call.args or {}),
                        "id": part.function_call.id or f"call_{i}",
                        "type": "tool_call",
                    }
                )
        raw_parts = [part.model_dump(mode="json", exclude_none=True) for part in parts]
        message = AIMessage(content=text, tool_calls=tool_calls, additional_kwargs={"gemini_parts": raw_parts})
        usage = response.usage_metadata
        if usage is not None:
            message.usage_metadata = {
                "input_tokens": usage.prompt_token_count or 0,
                "output_tokens": usage.candidates_token_count or 0,
                "total_tokens": usage.total_token_count or 0,
            }
        return ChatResult(generations=[ChatGeneration(message=message)])
