"""
Tests for the Stage 2 DeepVerifier (LLM-based verification).
"""

from __future__ import annotations

import os
import json
from unittest.mock import patch, MagicMock

import pytest

from src.models.hybrid_predictor import Verdict
# We will create this module next
from src.models.deep_verifier import DeepVerifier


@pytest.fixture
def mock_flow_features():
    """Mock network flow features."""
    return {
        "srcip": "192.168.1.100",
        "dstip": "10.0.0.5",
        "sport": 54321,
        "dsport": 80,
        "proto": "tcp",
        "spkts": 50,
        "dpkts": 48,
        "sbytes": 5000,
        "dbytes": 12000,
    }

def test_deep_verifier_initialization():
    """Test that DeepVerifier initializes with correct OpenRouter defaults."""
    os.environ["OPENROUTER_API_KEY"] = "sk-or-v1-testkey"
    verifier = DeepVerifier()
    
    assert verifier.model == "meta-llama/llama-3.1-8b-instruct:free"
    assert verifier.client.base_url == "https://openrouter.ai/api/v1/"


def test_format_prompt(mock_flow_features):
    """Test that flow features are correctly formatted into an LLM prompt."""
    verifier = DeepVerifier(api_key="test")
    prompt = verifier._format_prompt(mock_flow_features, stage_1_verdict="Suspicious")
    
    assert "192.168.1.100" in prompt
    assert "tcp" in prompt
    assert "Stage 1 flagged this as: Suspicious" in prompt


@patch("src.models.deep_verifier.OpenAI")
def test_verify_flow_success(mock_openai, mock_flow_features):
    """Test successful verification where LLM returns a valid JSON response."""
    # Setup the mock OpenAI client to return a fake JSON string
    mock_client_instance = MagicMock()
    mock_response = MagicMock()
    
    expected_json = json.dumps({
        "verdict": "Attack",
        "reason": "High packet count on port 80 with strange byte ratio."
    })
    
    mock_response.choices[0].message.content = expected_json
    mock_client_instance.chat.completions.create.return_value = mock_response
    mock_openai.return_value = mock_client_instance

    verifier = DeepVerifier(api_key="test")
    verdict, reason = verifier.verify_flow(mock_flow_features, "Suspicious")
    
    assert verdict == Verdict.ATTACK
    assert "High packet count" in reason


@patch("src.models.deep_verifier.OpenAI")
def test_verify_flow_api_error(mock_openai, mock_flow_features):
    """Test that Verifier falls back gracefully if the API crashes/times out."""
    mock_client_instance = MagicMock()
    # Force the API to raise an exception
    mock_client_instance.chat.completions.create.side_effect = Exception("API Timeout")
    mock_openai.return_value = mock_client_instance

    verifier = DeepVerifier(api_key="test")
    verdict, reason = verifier.verify_flow(mock_flow_features, "Suspicious")
    
    # Should fallback to whatever Stage 1 said if Stage 2 fails
    assert verdict == Verdict.SUSPICIOUS
    assert "api error" in reason.lower()
