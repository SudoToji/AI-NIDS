"""
End-to-End Pipeline Evaluation
==============================
Validates the complete Two-Stage Hybrid architecture by streaming 
events through the pipeline and capturing the LLM's responses.
"""

import os
import sys
import pandas as pd
from dotenv import load_dotenv

# Ensure we can import src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.features.unsw_processor import load_and_preprocess_unsw
from src.models.hybrid_predictor import HybridPredictor, Verdict

def run_evaluation():
    # Load env vars for OpenRouter API key
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
    load_dotenv(env_path)
    
    print("=" * 60)
    print("STARTING PHASE 4: TWO-STAGE PIPELINE EVALUATION")
    print("=" * 60)
    
    if not os.getenv("OPENROUTER_API_KEY"):
        print("ERROR: OPENROUTER_API_KEY is not set in .env")
        print("Please add it to run Stage 2 Verification.")
        return
        
    print("\n[1] Initializing Stage 1 Models (RF + AE)...")
    predictor = HybridPredictor(use_stage2=True)
    
    print("[2] Loading UNSW-NB15 Testing Data...")
    train_path = "data/unsw_nb15/Training and Testing Sets/UNSW_NB15_training-set.csv"
    test_path = "data/unsw_nb15/Training and Testing Sets/UNSW_NB15_testing-set.csv"
    
    # We load the split so we get the perfectly scaled/encoded Numpy array for the ML models
    split = load_and_preprocess_unsw(train_path, test_path)
    
    # We also load the raw CSV so we can pass the readable text to the LLM
    df_raw_test = pd.read_csv(test_path)
    
    events_processed = 0
    stage2_triggers = 0
    max_stage2_triggers = 3  # We'll just look at the first 3 Suspicious events to save time/API credits
    
    print("\n[3] Streaming events through pipeline...\n")
    
    for idx in range(len(split.x_test)):
        events_processed += 1
        
        # 1. Scaled Numpy array for the Machine Learning models
        scaled_features = split.x_test[idx]
        
        # 2. Raw Dictionary for the LLM
        raw_dict = df_raw_test.iloc[idx].to_dict()
        actual_cat = raw_dict.pop('attack_cat', 'Unknown')
        raw_dict.pop('label', None)
        raw_dict.pop('id', None)
        
        # 3. Predict!
        result = predictor.predict(features=scaled_features, raw_features=raw_dict)
        
        # 4. Display Results if Stage 2 was triggered
        if result.final_verdict == Verdict.SUSPICIOUS or result.stage2_reason is not None:
            stage2_triggers += 1
            print("-" * 60)
            print(f"!!! EVENT #{events_processed} | Ground Truth: {actual_cat}")
            print(f"   Stage 1 RF Prediction: {result.rf_label} (Conf: {result.rf_confidence:.2f})")
            print(f"   Stage 1 AE Anomaly:    {result.ae_is_anomaly} (Score: {result.ae_anomaly_score:.4f})")
            print(f"   --> Triggered Stage 2 DeepVerifier <--")
            print(f"   [LLM] Stage 2 Verdict: {result.final_verdict}")
            print(f"   [LLM] Stage 2 Reason:  {result.stage2_reason}")
            print("-" * 60)
            
            if stage2_triggers >= max_stage2_triggers:
                break
                
    print("\nEvaluation Complete!")
    print(f"Processed {events_processed} packets until we found {max_stage2_triggers} suspicious flows.")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore") # Ignore pandas warnings for clean output
    run_evaluation()
