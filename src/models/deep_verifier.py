"""
Stage 2 Deep Verifier
=====================
Uses a Large Language Model (via OpenRouter API) acting as a SOC Analyst
to verify ambiguous or suspicious network flows from Stage 1.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Tuple

from openai import OpenAI

from src.models.hybrid_predictor import Verdict

LOGGER = logging.getLogger(__name__)


class DeepVerifier:
    """Uses an LLM API to deeply verify network anomalies."""

    def __init__(
        self, 
        api_key: str | None = None, 
        model: str = "openai/gpt-oss-20b:free"
    ):
        """
        Initialize the DeepVerifier.
        
        Args:
            api_key: OpenRouter API key. Defaults to OPENROUTER_API_KEY env var.
            model: The LLM model string to use on OpenRouter.
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model
        
        # We use the official OpenAI SDK but point it to OpenRouter's URL
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1/",
            api_key=self.api_key or "dummy-key-for-tests",
        )

    def _format_prompt(self, features: Dict[str, Any], stage_1_verdict: str) -> str:
        """Format the network features into a readable string for the LLM."""
        prompt = f"Stage 1 flagged this as: {stage_1_verdict}\n\n"
        prompt += "Network Flow Features:\n"
        
        for k, v in features.items():
            # Skip very long or unhelpful features if necessary, but we'll include all for now
            prompt += f"- {k}: {v}\n"
            
        return prompt

    def verify_flow(self, features: Dict[str, Any], stage_1_verdict: str) -> Tuple[str, str]:
        """
        Sends the flow to the LLM for deep verification.
        
        Args:
            features: Dictionary of network flow statistics.
            stage_1_verdict: What the Random Forest ensemble thought it was.
            
        Returns:
            Tuple of (Final Verdict, Analyst Reason string)
        """
        try:
            system_prompt = (
                "You are an expert Senior SOC Analyst AI. Analyze the following network flow features. "
                "Respond ONLY with a valid JSON object containing exactly two keys: "
                "'verdict' (must be exactly 'Benign', 'Suspicious', or 'Attack') and "
                "'reason' (a 1-sentence technical explanation of why).\n"
                "Example: {\"verdict\": \"Attack\", \"reason\": \"High packet count and short IAT indicates a UDP flood.\"}"
            )
            
            user_prompt = self._format_prompt(features, stage_1_verdict)
            
            # Make the API call
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,  # Low temperature for highly deterministic analysis
                max_tokens=150,
                timeout=5.0       # Failsafe: Don't block the live sniffer for >5 seconds
            )
            
            # Parse the response
            content = response.choices[0].message.content
            result = json.loads(content)
            
            verdict_str = result.get("verdict", stage_1_verdict)
            reason = result.get("reason", "No specific reason provided by LLM.")
            
            # Map back to our exact Verdict constants safely
            v_lower = str(verdict_str).lower()
            if "attack" in v_lower:
                final_verdict = Verdict.ATTACK
            elif "benign" in v_lower or "normal" in v_lower:
                final_verdict = Verdict.BENIGN
            else:
                final_verdict = Verdict.SUSPICIOUS
                
            return final_verdict, reason
            
        except Exception as e:
            # Failsafe: If the API times out or returns bad JSON, gracefully fall back
            LOGGER.error("DeepVerifier API Error: %s", e)
            return stage_1_verdict, f"Stage 2 Verification Failed (API Error: {str(e)}). Falling back to Stage 1."
