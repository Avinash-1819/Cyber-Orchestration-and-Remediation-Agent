"""
Sentinel AI — LLM Client Service
Wraps all Gemini API calls with model routing, retry/backoff,
structured output (response_schema), and Pydantic validation.
"""
import asyncio
import json
from typing import Any, Callable, Optional, Type, TypeVar

import structlog
from google import genai
from google.genai import types as genai_types
from pydantic import BaseModel, ValidationError

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

# Hard ceiling for a single model call so a slow/down API never hangs the pipeline.
# When exceeded, the agent's deterministic analysis engine takes over.
_LLM_CALL_TIMEOUT_SECONDS = 25.0


class LLMClient:
    """
    Centralized LLM client for all Sentinel AI model calls.
    - Model routing per agent role
    - Structured JSON output via response_schema
    - Pydantic validation with single retry
    - Bounded per-call timeout
    - Deterministic offline analysis engine as the real fallback (never fabricated data)
    """

    def __init__(self) -> None:
        if settings.GEMINI_API_KEY and settings.GEMINI_API_KEY != "your-google-gemini-api-key":
            self._client = genai.Client(api_key=settings.GEMINI_API_KEY)
            log.info("llm_client_initialized", pro=settings.LLM_MODEL_PRO,
                     flash=settings.LLM_MODEL_FLASH, flash_lite=settings.LLM_MODEL_FLASH_LITE)
        else:
            self._client = None
            log.warning("llm_client_offline_mode", message="GEMINI_API_KEY not configured. Agents will use the deterministic analysis engine.")

    @property
    def is_configured(self) -> bool:
        return self._client is not None

    def _resolve_model(self, model_role: str, model_override: Optional[str]) -> str:
        if model_override:
            return model_override
        return _MODEL_MAP.get(model_role, settings.LLM_MODEL_FLASH)

    def _fill_missing_fields(self, data: dict, output_schema: Type[T]) -> dict:
        """Fill any missing required fields with honest neutral defaults."""
        for field_name, field_info in output_schema.model_fields.items():
            if field_name not in data or data[field_name] is None:
                annotation_str = str(field_info.annotation)
                if "str" in annotation_str:
                    data[field_name] = "Analysis unavailable — no LLM response received."
                elif "float" in annotation_str:
                    data[field_name] = 0.0
                elif "int" in annotation_str:
                    data[field_name] = 0
                elif "bool" in annotation_str:
                    data[field_name] = False
                elif "list" in annotation_str or "List" in annotation_str:
                    data[field_name] = []
                elif "dict" in annotation_str or "Dict" in annotation_str:
                    data[field_name] = {}
                else:
                    data[field_name] = None
        return data

    async def generate_structured(
        self,
        prompt: str,
        output_schema: Type[T],
        model_role: str = MODEL_FLASH,
        model_override: Optional[str] = None,
        system_instruction: Optional[str] = None,
        temperature: float = 0.1,
        agent_name: str = "unknown",
        fallback_factory: Optional[Callable[[], T]] = None,
    ) -> T:
        """
        Generate structured output from the LLM and validate against output_schema.
        When the client is unconfigured or all models fail, the provided
        fallback_factory (the agent's real deterministic analysis engine) is used.
        """
        if self._client is None:
            if fallback_factory is not None:
                return fallback_factory()
            return output_schema.model_validate(self._fill_missing_fields({}, output_schema))

        primary_model = self._resolve_model(model_role, model_override)
        fallback_models = [primary_model, "gemini-2.0-flash"]
        candidate_models = list(dict.fromkeys(fallback_models))

        last_error = None
        for model_name in candidate_models:
            try:
                log.debug("llm_call_start", agent=agent_name, model=model_name, prompt_len=len(prompt))
                config = genai_types.GenerateContentConfig(
                    temperature=temperature,
                    response_mime_type="application/json",
                    response_schema=output_schema,
                    system_instruction=system_instruction or (
                        "You are a cybersecurity AI assistant. Respond ONLY with valid JSON matching "
                        "the provided schema. Be precise, accurate, and security-focused."
                    ),
                )

                async def _call_once(model_name: str = model_name) -> T:
                    loop = asyncio.get_running_loop()
                    future = loop.run_in_executor(
                        None,
                        lambda: self._client.models.generate_content(
                            model=model_name,
                            contents=prompt,
                            config=config,
                        ),
                    )
                    response = await asyncio.wait_for(future, timeout=_LLM_CALL_TIMEOUT_SECONDS)
                    raw_text = response.text or ""
                    log.debug(
                        "llm_call_complete",
                        agent=agent_name,
                        model=model_name,
                        output_tokens=getattr(response.usage_metadata, "candidates_token_count", 0),
                        input_tokens=getattr(response.usage_metadata, "prompt_token_count", 0),
                    )
                    try:
                        parsed = json.loads(raw_text)
                        return output_schema.model_validate(parsed)
                    except (json.JSONDecodeError, ValidationError) as ve:
                        raise SentinelValidationError(
                            agent_name=agent_name,
                            raw_response=raw_text[:500],
                            validation_error=str(ve),
                        ) from ve

                return await _call_once()
            except Exception as e:
                log.warning("llm_model_failed", agent=agent_name, model=model_name, error=str(e)[:200])
                last_error = e

        log.warning("llm_all_models_failed_using_deterministic_engine", agent=agent_name, error=str(last_error))
        if fallback_factory is not None:
            return fallback_factory()
        return output_schema.model_validate(self._fill_missing_fields({}, output_schema))

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
        Generate free-form text with a bounded timeout.
        """
        if self._client is None:
            return ""

        model_name = self._resolve_model(model_role, model_override)

        try:
            config = genai_types.GenerateContentConfig(
                temperature=temperature,
                system_instruction=system_instruction,
            )
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(
                None,
                lambda: self._client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config,
                ),
            )
            response = await asyncio.wait_for(future, timeout=_LLM_CALL_TIMEOUT_SECONDS)
            return response.text or ""
        except Exception as e:
            log.warning("llm_text_failed", agent=agent_name, error=str(e)[:200])
            return ""


# Global singleton
_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client

