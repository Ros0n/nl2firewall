"""
Groq API client.

Uses openai/gpt-oss-120b via the Groq SDK (AsyncGroq for async FastAPI).
The model is OpenAI-compatible, so the interface is standard chat completions.

Key choices:
  - response_format={"type": "json_object"} for structured outputs (no regex hacks)
  - reasoning_effort="medium" — gives CoT reasoning without being too slow
  - stream=False — we need the full response before parsing JSON
  - temperature=0 for deterministic structured output
  - AsyncGroq for non-blocking calls inside FastAPI/LangGraph
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from groq import AsyncGroq

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class GroqClient:
    """
    Async wrapper around the Groq API for openai/gpt-oss-120b.

    Usage:
        client = GroqClient()
        result = await client.generate_json(system_prompt, user_message)
        text   = await client.generate_text(system_prompt, user_message)
    """

    def __init__(self) -> None:
        settings = get_settings()
        # AsyncGroq picks up GROQ_API_KEY from env automatically
        # but we pass it explicitly so settings stay the single source of truth
        self._client = AsyncGroq(api_key=settings.groq_api_key)
        self._model = settings.groq_model

    async def generate_json(
        self,
        system_prompt: str,
        user_message: str,
        max_retries: int = 3,
    ) -> dict[str, Any]:
        """
        Call the model and return a parsed JSON dict.

        Uses response_format={"type": "json_object"} so the model is
        constrained to emit valid JSON — no regex extraction needed.
        Falls back to manual extraction on the rare parse failure.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                response = await self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    temperature=0,  # deterministic for ACL generation
                    max_completion_tokens=4096,
                    top_p=1,
                    reasoning_effort="medium",  # CoT reasoning, balanced speed
                    stream=False,
                    stop=None,
                    response_format={"type": "json_object"},
                )

                raw_text = response.choices[0].message.content or ""
                logger.debug(
                    f"Groq raw response (attempt {attempt + 1}):\n{raw_text[:400]}"
                )

                parsed = self._extract_json(raw_text)
                return parsed

            except (json.JSONDecodeError, ValueError) as e:
                last_error = e
                logger.warning(f"JSON parse failed on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    # Add correction nudge and retry
                    messages.append(
                        {
                            "role": "assistant",
                            "content": raw_text if "raw_text" in dir() else "",
                        }
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Your response was not valid JSON. "
                                "Output ONLY a JSON object starting with { and ending with }. "
                                "No markdown, no backticks, no explanation text."
                            ),
                        }
                    )
                    await asyncio.sleep(0.5 * (attempt + 1))

            except Exception as e:
                last_error = e
                logger.warning(f"API call failed on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.0 * (attempt + 1))

        raise ValueError(
            f"Failed to get valid JSON from Groq after {max_retries} attempts. "
            f"Last error: {last_error}"
        )

    async def generate_text(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.3,
    ) -> str:
        """
        Call the model and return plain text (for explanation generation).
        No JSON mode — just natural language output.
        """
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=temperature,
            max_completion_tokens=1024,
            top_p=1,
            reasoning_effort="medium",
            stream=False,
            stop=None,
        )
        return response.choices[0].message.content or ""

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        """
        Extract JSON from model output.
        With json_object mode this is usually a no-op,
        but handles edge cases like leading/trailing whitespace.
        """
        text = text.strip()

        # Strip markdown fences if somehow present
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
        text = text.strip()

        # Direct parse (should always work with json_object mode)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Fallback: find first { ... } block
        start = text.find("{")
        if start == -1:
            raise ValueError("No JSON object found in response")

        depth, end = 0, -1
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        if end == -1:
            raise ValueError("Unmatched braces in JSON response")

        return json.loads(text[start:end])


# ─── Singleton ────────────────────────────────────────────────────────────────

_client: GroqClient | None = None


def get_groq_client() -> GroqClient:
    global _client
    if _client is None:
        _client = GroqClient()
    return _client
