"""
Sentinel AI — LLM Client Service
Wraps all Gemini API calls with model routing, retry/backoff,
structured output (response_schema), and Pydantic validation.
"""
import asyncio
import json
from typing import Any, Optional, Type, TypeVar

import structlog
from google import genai
from google.genai import types as genai_types
from pydantic import BaseModel, ValidationError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.exceptions import ValidationError as SentinelValidationError

log = structlog.get_logger(__name__)

T = TypeVar("T", bound=BaseModel)

# Model role constants (referenced by agents)
MODEL_PRO = "pro"
MODEL_FLASH = "flash"
MODEL_FLASH_LITE = "flash_lite"

_MODEL_MAP = {
    MODEL_PRO: settings.LLM_MODEL_PRO,
    MODEL_FLASH: settings.LLM_MODEL_FLASH,
    MODEL_FLASH_LITE: settings.LLM_MODEL_FLASH_LITE,
}


class LLMClient:
    """
    Centralized LLM client for all Sentinel AI model calls.
    - Model routing per agent role
    - Structured JSON output via response_schema
    - Pydantic validation with single retry
    - Token usage logging
    """

    def __init__(self) -> None:
        if not settings.GEMINI_API_KEY:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured. Set it in your .env file."
            )
        self._client = genai.Client(api_key=settings.GEMINI_API_KEY)
        log.info("llm_client_initialized", pro=settings.LLM_MODEL_PRO,
                 flash=settings.LLM_MODEL_FLASH, flash_lite=settings.LLM_MODEL_FLASH_LITE)

    def _resolve_model(self, model_role: str, model_override: Optional[str]) -> str:
        if model_override:
            return model_override
        return _MODEL_MAP.get(model_role, settings.LLM_MODEL_FLASH)

    async def generate_structured(
        self,
        prompt: str,
        output_schema: Type[T],
        model_role: str = MODEL_FLASH,
        model_override: Optional[str] = None,
        system_instruction: Optional[str] = None,
        temperature: float = 0.1,
        agent_name: str = "unknown",
    ) -> T:
        """
        Generate structured output from the LLM and validate against output_schema.
        Retries once on validation failure, then raises SentinelValidationError.
        """
        primary_model = self._resolve_model(model_role, model_override)
        fallback_models = [primary_model, "gemini-2.0-flash", "gemini-3.5-flash-lite", "gemini-1.5-flash"]
        # Deduplicate while preserving order
        candidate_models = list(dict.fromkeys(fallback_models))

        last_error = None
        for model_name in candidate_models:
            try:
                @retry(
                    retry=retry_if_exception_type(Exception),
                    stop=stop_after_attempt(3),
                    wait=wait_exponential(multiplier=2, min=3, max=30),
                    reraise=True,
                )
                async def _call_with_retry(attempt_prompt: str) -> T:
                    log.debug("llm_call_start", agent=agent_name, model=model_name, attempt_prompt_len=len(attempt_prompt))
                    config = genai_types.GenerateContentConfig(
                        temperature=temperature,
                        response_mime_type="application/json",
                        response_schema=output_schema,
                        system_instruction=system_instruction or (
                            "You are a cybersecurity AI assistant. Respond ONLY with valid JSON matching "
                            "the provided schema. Be precise, accurate, and security-focused."
                        ),
                    )
                    response = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self._client.models.generate_content(
                            model=model_name,
                            contents=attempt_prompt,
                            config=config,
                        ),
                    )
                    raw_text = response.text or ""
                    log.debug(
                        "llm_call_complete",
                        agent=agent_name,
                        model=model_name,
                        output_tokens=getattr(response.usage_metadata, "candidates_token_count", 0),
                        input_tokens=getattr(response.usage_metadata, "prompt_token_count", 0),
                    )
                    # Validate against Pydantic schema
                    try:
                        parsed = json.loads(raw_text)
                        return output_schema.model_validate(parsed)
                    except (json.JSONDecodeError, ValidationError) as ve:
                        raise SentinelValidationError(
                            agent_name=agent_name,
                            raw_response=raw_text,
                            validation_error=str(ve),
                        ) from ve

                return await _call_with_retry(prompt)
            except Exception as e:
                log.warning("llm_model_failed", agent=agent_name, model=model_name, error=str(e)[:200])
                last_error = e

        raise last_error or RuntimeError("All model fallbacks failed")

    async def generate_text(
        self,
        prompt: str,
        model_role: str = MODEL_FLASH,
        model_override: Optional[str] = None,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2,
        agent_name: str = "unknown",
    ) -> str:
        """
        Generate free-form text (used for prompts where schema enforcement isn't needed).
        """
        model_name = self._resolve_model(model_role, model_override)

        @retry(
            retry=retry_if_exception_type(Exception),
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            reraise=True,
        )
        async def _call_with_retry() -> str:
            config = genai_types.GenerateContentConfig(
                temperature=temperature,
                system_instruction=system_instruction,
            )
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config,
                ),
            )
            log.debug(
                "llm_text_call_complete",
                agent=agent_name,
                model=model_name,
                output_tokens=getattr(response.usage_metadata, "candidates_token_count", 0),
            )
            return response.text or ""

        return await _call_with_retry()


# Global singleton
_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client
