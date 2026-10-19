"""Offline tests for the native Gemini chat model: no network calls, only the message conversion
that replaces what langchain-google-genai does not do correctly for Gemini 3 (preserving
thought_signature across turns). See changegate/gemini_native.py for why this exists."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from changegate.gemini_native import ChatGeminiNative


def make_model() -> ChatGeminiNative:
    return ChatGeminiNative(model="gemini-3.8-flash", api_key="unused-in-these-tests", temperature=0.0)


def test_bind_tools_builds_function_declarations():
    @tool
    def add(a: int, b: int) -> int:
        """add two numbers"""
        return a + b

    bound = make_model().bind_tools([add])
    assert bound._tools is not None
    decl = bound._tools[0].function_declarations[0]
    assert decl.name == "add"
    assert decl.parameters_json_schema["required"] == ["a", "b"]


def test_ai_message_with_gemini_parts_round_trips_thought_signature():
    model = make_model()
    raw_parts = [
        {
            "function_call": {"name": "edit_file", "args": {"path": "main.tf"}, "id": "call_1"},
            "thought_signature": "AAH_aGVsbG8=",
        }
    ]
    history = [
        SystemMessage(content="system prompt"),
        HumanMessage(content="do the thing"),
        AIMessage(content="", tool_calls=[{"name": "edit_file", "args": {"path": "main.tf"}, "id": "call_1", "type": "tool_call"}], additional_kwargs={"gemini_parts": raw_parts}),
        ToolMessage(content="ok", tool_call_id="call_1", name="edit_file"),
    ]
    system_text, contents = model._to_contents(history)
    assert system_text == "system prompt"
    # user, model (with the stored thought_signature), user (function response)
    assert [c.role for c in contents] == ["user", "model", "user"]
    model_turn = contents[1]
    assert model_turn.parts[0].thought_signature == b"\x00\x01\xffhello"
    response_turn = contents[2]
    assert response_turn.parts[0].function_response.name == "edit_file"
    assert response_turn.parts[0].function_response.id == "call_1"


def test_ai_message_without_gemini_parts_falls_back_to_tool_calls():
    model = make_model()
    history = [
        AIMessage(content="", tool_calls=[{"name": "submit", "args": {"summary": "done"}, "id": "call_2", "type": "tool_call"}]),
    ]
    _, contents = model._to_contents(history)
    assert len(contents) == 1
    part = contents[0].parts[0]
    assert part.function_call.name == "submit"
    assert part.thought_signature is None
