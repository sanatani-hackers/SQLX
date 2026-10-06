import os
from typing import List, Dict, Any, Optional

class LLMProvider:
    def generate(self, messages: List[Dict[str, Any]], model: str = "", tools: List[Dict[str, Any]] = None) -> Any:
        raise NotImplementedError("Subclasses must implement generate")

class DummyProvider(LLMProvider):
    """
    Fallback provider used when no real LLM is configured.
    Tells the user exactly how to configure a real provider instead of
    pretending to be an AI.
    """
    def generate(self, messages: List[Dict[str, Any]], model: str = "", tools: List[Dict[str, Any]] = None) -> Any:
        return (
            "⚠️  No real AI provider is configured — I'm running in offline mode.\n\n"
            "Set up a provider with one of these options:\n"
            "  • Gemini (free):  export GEMINI_API_KEY=...   then  ./sqlx.py agent --provider gemini\n"
            "  • Groq   (free):  export GROQ_API_KEY=...     then  ./sqlx.py agent --provider groq\n"
            "  • Ollama (local): install ollama, run `ollama pull llama3.2`, then ./sqlx.py agent --provider ollama\n"
            "  • OpenAI:         export OPENAI_API_KEY=...   then  ./sqlx.py agent --provider openai\n\n"
            "Tip: use the TUI (`./sqlx.py tui`) to manage targets without needing an AI provider."
        )


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, api_key: str = None, base_url: str = None, default_model: str = "gpt-4o-mini"):
        from openai import OpenAI
        
        self.client = OpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=base_url
        )
        self.default_model = default_model
        
    def generate(self, messages: List[Dict[str, Any]], model: str = "", tools: List[Dict[str, Any]] = None) -> Any:
        target_model = model or self.default_model
        kwargs = {
            "model": target_model,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
            
        response = self.client.chat.completions.create(**kwargs)
        message = response.choices[0].message
        
        # If the model called a tool, return the whole message object so the agent can process it
        if message.tool_calls:
            return message
            
        return message.content

class ProviderFactory:
    @staticmethod
    def create(provider_name: str, **kwargs) -> LLMProvider:
        provider_name = provider_name.lower()
        if provider_name == "dummy":
            return DummyProvider()
        elif provider_name == "openai":
            return OpenAICompatibleProvider(**kwargs)
        elif provider_name == "groq":
            kwargs["base_url"] = "https://api.groq.com/openai/v1"
            kwargs["default_model"] = kwargs.get("default_model", "llama3-70b-8192")
            if "api_key" not in kwargs and "GROQ_API_KEY" in os.environ:
                kwargs["api_key"] = os.environ["GROQ_API_KEY"]
            return OpenAICompatibleProvider(**kwargs)
        elif provider_name == "openrouter":
            kwargs["base_url"] = "https://openrouter.ai/api/v1"
            kwargs["default_model"] = kwargs.get("default_model", "anthropic/claude-3-haiku")
            if "api_key" not in kwargs and "OPENROUTER_API_KEY" in os.environ:
                kwargs["api_key"] = os.environ["OPENROUTER_API_KEY"]
            return OpenAICompatibleProvider(**kwargs)
        elif provider_name == "agentrouter":
            kwargs["base_url"] = "https://api.agentrouter.com/v1"
            kwargs["default_model"] = kwargs.get("default_model", "agentrouter-default")
            if "api_key" not in kwargs and "AGENTROUTER_API_KEY" in os.environ:
                kwargs["api_key"] = os.environ["AGENTROUTER_API_KEY"]
            return OpenAICompatibleProvider(**kwargs)
        elif provider_name == "gemini":
            # Use Google's official OpenAI-compatible endpoint for seamless tool calling support
            kwargs["base_url"] = "https://generativelanguage.googleapis.com/v1beta/openai/"
            kwargs["default_model"] = kwargs.get("default_model", "gemini-2.5-flash")
            if "api_key" not in kwargs and "GEMINI_API_KEY" in os.environ:
                kwargs["api_key"] = os.environ["GEMINI_API_KEY"]
            return OpenAICompatibleProvider(**kwargs)
        elif provider_name == "llmsrelay":
            kwargs["base_url"] = "https://api.llmsrelay.com/v1"
            kwargs["default_model"] = kwargs.get("default_model", "gpt-5.5")
            if "api_key" not in kwargs and "LLMSRELAY_API_KEY" in os.environ:
                kwargs["api_key"] = os.environ["LLMSRELAY_API_KEY"]
            return OpenAICompatibleProvider(**kwargs)
        elif provider_name == "ollama":
            # Ollama runs locally and exposes an OpenAI-compatible API
            # Default host: http://localhost:11434  (override with OLLAMA_HOST env var)
            ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
            kwargs["base_url"] = f"{ollama_host.rstrip('/')}/v1"
            kwargs["default_model"] = kwargs.get("default_model", "gpt-oss:120b-cloud")
            # Ollama doesn't require an API key, but the openai client requires a non-empty string
            kwargs["api_key"] = kwargs.get("api_key") or os.environ.get("OLLAMA_API_KEY") or "ollama"
            return OpenAICompatibleProvider(**kwargs)
        else:
            raise ValueError(f"Unknown provider: {provider_name}. Available: dummy, openai, gemini, groq, openrouter, agentrouter, llmsrelay, ollama")
