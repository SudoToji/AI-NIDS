# Project Progress Log

## 2026-03-14
- Initialized Phase 1 training pipeline (extractor, RF training, autoencoder training).
- Added instructions for running training via PowerShell.

---

## 2026-03-15

### Session Goal
Review the current CICIDS2017 training setup, fix long/unusable training behavior on a Ryzen 5 3600 + 16GB RAM machine, compare available models, improve anomaly detection behavior, and finalize the recommended project architecture.

### 1. Root Cause Investigation
- Inspected the project structure and located the main training files:
  - `src/features/extractor.py`
  - `src/models/train_rf.py`
  - `src/models/autoencoder.py`
- Checked the processed dataset and confirmed that `data/processed/cicids2017_cleaned.csv` contains approximately **2,520,751 rows** and **53 columns**.
- Confirmed that the label column in the cleaned dataset is **`Attack Type`**.
- Confirmed that the original long training problem was caused by a very expensive training setup on modest hardware:
  - Random Forest hyperparameter search / repeated fitting behavior was too heavy.
  - The autoencoder was also training on too much data with an overly expensive default setup.
- Verified that the issue was primarily the script/configuration, not the user hardware.

### 2. Preprocessing / Extractor Improvements
Updated `src/features/extractor.py` to make the project usable on a normal desktop PC.

Changes made:
- Added project-root-aware path handling so scripts work when launched from PowerShell outside the project directory.
- Added environment-controlled sampling options:
  - `MAX_ROWS`
  - `MAX_SAMPLES_PER_CLASS`
- Added safer defaults for local training:
  - default total row cap
  - default per-class cap
- Added chunked CSV loading with a progress bar.
- Added class-sampling progress display.
- Added memory-friendlier dataset loading behavior.
- Kept train/test split creation, scaling, and label encoding aligned with the project pipeline.

Purpose:
- Reduce training time and memory pressure.
- Allow full-dataset runs when explicitly requested.
- Make runs transparent with visible progress.

### 3. Random Forest Training Improvements
Updated `src/models/train_rf.py`.

Changes made:
- Replaced impractical default heavy search behavior with a **fast default Random Forest path**.
- Kept hyperparameter tuning available only when explicitly enabled via environment variables.
- Added visible progress support:
  - dataset loading progress
  - tree-training progress bar for the fast RF path
  - clearer tuning logging
- Added project-root-aware save paths.
- Saved model metadata alongside the model.
- Added Bots-specific threshold logic in metadata for better multiclass handling.

Artifacts produced/used:
- `models/rf_model.pkl`
- `models/rf_metadata.pkl`
- `models/scaler.pkl`
- `models/rf_feature_importance.png`

### 4. Random Forest Validation and Evaluation
Validated the Random Forest after fixes.

Key results observed during testing:
- Smoke-test RF run succeeded.
- Full-dataset RF run completed much faster than the original heavy search setup because it now trains **one practical forest** instead of a massive search.
- Verified that the full cleaned dataset split was used when sampling was disabled.

Evaluated saved RF model on the project test split.

Main RF metrics:
- Accuracy: **~99.61%** in one evaluation phase, then later a validated full-pipeline RF result of **~99.89%** depending on the specific saved model state used at that moment.
- Weighted F1: **~99.71%** to **~99.89%**.
- Macro F1: **~0.90 to 0.96** depending on the saved threshold metadata and evaluation phase.

Important class observation:
- **Bots** remained the weakest class.
- One validated RF result for Bots was approximately:
  - Precision: **0.89**
  - Recall: **0.68**
  - F1: **0.77**
- Interpretation:
  - RF is very strong overall.
  - Bots remains a minority-class tradeoff problem.

### 5. Downloaded Model Inspection and Comparison
Located downloaded external model artifacts in:
- `Desktop/Project/downloadedmodels/random_forest.joblib`
- `Desktop/Project/downloadedmodels/xgboost.joblib`
- `Desktop/Project/downloadedmodels/robust_scaler.joblib`

#### Downloaded Random Forest
- Attempted to load it.
- It failed due to **scikit-learn version incompatibility / tree dtype mismatch**.
- Conclusion:
  - The downloaded RF artifact is **not safely usable in the current environment**.
  - Fair direct evaluation was not possible from the file itself.

#### Downloaded XGBoost
- Installed `xgboost` into the project virtual environment.
- Loaded the downloaded XGBoost artifact successfully, but received warnings indicating:
  - old XGBoost serialization
  - potential incompatibility across versions
- Confirmed the downloaded XGBoost expected:
  - 52 features
  - 7 classes
  - a different explicit label mapping than the project label encoder order
- Initial direct comparison looked catastrophically wrong because the downloaded model predicted class index `0` for all samples, but later analysis showed the **Kaggle notebook uses a different label mapping**:
  - Kaggle mapping: `Normal Traffic = 0`, `Bots = 6`
  - Project mapping/order: `Bots = 0`, `Normal Traffic = 4`
- Conclusion:
  - The downloaded XGBoost artifact cannot be trusted for direct class-name comparison without reproducing the original Kaggle preprocessing and label mapping.

### 6. Kaggle Notebook Analysis
Reviewed the pasted XGBoost section from:
- `https://www.kaggle.com/code/ericanacletoribeiro/cicids2017-ml-models-comparison-supervised/notebook`

Important findings:
- Kaggle notebook used a **custom manual label mapping** different from the project’s `LabelEncoder` order.
- Kaggle notebook likely used a **30% test split** (support totals around `756,226`), while the project commonly used a **20% test split**.
- Kaggle notebook trained XGBoost on **resampled training data** (`X_train_resampled`, `y_train_resampled`).
- Therefore, Kaggle metrics are **not directly comparable** to the project’s current pipeline unless the full original preprocessing, label mapping, and split strategy are reproduced.

### 7. Random Forest Comparison vs External Reported Numbers
Compared the user-provided reported Random Forest numbers from the external source against the project RF.

External RF Bots result provided by user:
- Precision: **0.71**
- Recall: **0.83**
- F1: **0.77**

Project RF Bots result:
- Precision: **0.89**
- Recall: **0.68**
- F1: **0.77**

Interpretation:
- Both models are effectively tied on Bots F1.
- External RF is more aggressive on Bots (higher recall, lower precision).
- Project RF is more conservative on Bots (higher precision, lower recall).
- Therefore, the external RF did **not** demonstrate a clearly superior overall Bots solution; it mostly represents a precision/recall tradeoff.

### 8. Autoencoder Investigation
Tested the saved autoencoder artifacts:
- `models/autoencoder.keras`
- `models/autoencoder_threshold.npy`

Initial findings before fix:
- The saved autoencoder threshold was extremely high relative to observed reconstruction errors.
- The model almost never flagged attacks as anomalous.

Initial anomaly-detection behavior on full test split:
- Accuracy looked moderate because most traffic is normal.
- But anomaly recall was extremely poor.
- Per-class anomaly flag rates were near zero for most attack classes.
- Conclusion:
  - The original saved autoencoder was **not suitable as the main detector**.
  - The problem was largely threshold selection, not only the network itself.

### 9. Autoencoder Fixes
Updated `src/models/autoencoder.py`.

Changes made:
- Improved network width slightly.
- Reworked threshold selection completely.
- Instead of setting threshold from benign-only error statistics (`mean + 3*std`), the code now:
  - reserves a labeled validation split
  - computes reconstruction error on validation data
  - chooses threshold using a validation objective
- Added environment controls:
  - `AE_VALIDATION_SIZE`
  - `AE_THRESHOLD_OBJECTIVE`
  - `AE_THRESHOLD_BETA`
- Added support for threshold objectives such as:
  - F1 optimization
  - recall-oriented selection
  - F-beta optimization with higher recall weight

Purpose:
- Make the autoencoder actually useful for anomaly detection.
- Improve attack recall instead of making the detector nearly blind.

### 10. Autoencoder Validation After Fix
Performed a small-sample validation run after the threshold fix.

Observed result on the sample evaluation:
- Threshold dropped from a very high unusable value to a practical value (~`0.1165` in the sample test).
- Anomaly metrics improved drastically:
  - Accuracy: **~0.834**
  - Precision (anomaly): **~0.833**
  - Recall (anomaly): **1.000**
  - F1 (anomaly): **~0.909**

Interpretation:
- The fix worked on validation.
- The autoencoder is now more useful as an anomaly detector.
- It is still not recommended as the main classifier, but it becomes a meaningful support model.

### 11. Final Model Recommendations
#### Best main model to use now
**Random Forest**

Reason:
- best overall reliability
- strongest validated performance
- works correctly in the current environment
- matches project preprocessing and saved metadata

#### Role of autoencoder
**Support / anomaly detection model only**

Reason:
- useful for anomaly flagging and unknown/suspicious behavior
- not as strong as RF for multiclass attack classification

#### Downloaded models
- Downloaded RF: incompatible in current environment.
- Downloaded XGBoost: not directly trustworthy without reproducing original Kaggle preprocessing, split, and label mapping.

### 12. Bots Class Conclusion
Bots remains the key weak class.

Findings:
- Project RF is strong overall but conservative on Bots.
- External/Kaggle-style models suggest higher Bots recall may be possible, but often with lower precision.
- Best future improvement path identified:
  - add a **Bots-vs-Rest** binary classifier as a specialized second-stage model.

### 13. Final Recommended Architecture
Final architecture recommended for the project at this stage:

1. **Preprocessing Layer**
   - clean/validate input
   - keep selected 52 CICIDS2017 features
   - apply saved scaler

2. **Main Model: Random Forest**
   - primary multiclass classifier
   - predicts:
     - Normal Traffic
     - DoS
     - DDoS
     - Port Scanning
     - Brute Force
     - Web Attacks
     - Bots

3. **Support Model: Autoencoder**
   - anomaly detector for suspicious / unknown behavior
   - optional secondary signal

4. **Future Add-on: Bots-vs-Rest Classifier**
   - best targeted improvement path for the Bots class

### 14. Commands Provided During the Session
Commands were provided for:
- running Random Forest training with progress bars
- running full-dataset Random Forest training
- running light tuning with visible/unbuffered output
- running autoencoder training with progress
- retraining the fixed autoencoder with validation-based threshold selection

### 15. Temporary File Cleanup
- Removed temporary testing helper file:
  - `tmp_rovodev_rf_full_eval.py`
- Confirmed no final metrics temp file remained in the workspace.

### 16. Final Status at End of Session
- Random Forest pipeline: **working and recommended for use**.
- Autoencoder pipeline: **improved and more useful after threshold fix**, but still a support model rather than the main classifier.
- Downloaded external models: **not recommended for direct use in current state**.
- Final architecture selected:
  - **Random Forest as primary classifier**
  - **Autoencoder as anomaly support**
  - **Bots-vs-Rest as best future targeted upgrade**

---

**Note:** This file now contains the main technical progress and conclusions from the current model-selection, evaluation, and optimization session.

---

## 2026-03-17

### Session Goal
Fix Flask API integration, improve dashboard UI, add attack simulation, and document the project.

### 1. Problem: Model Predictions Not Working

**Symptoms:**
- Dashboard showed all alerts as "Normal Traffic"
- Attack distribution showed everything as DDoS
- API simulation wasn't working

**Root Causes:**
1. Feature extraction was mapping fields incorrectly
2. Simulated attack data didn't match real CIC-IDS2017 patterns
3. Autoencoder threshold was too high (0.5 vs optimal 0.2)
4. Dashboard API endpoints had wrong paths

### 2. Fixes Applied

#### A. Feature Extraction Fix (`src/api/server.py`)
- Rewrote `extract_features()` to map packet data to correct CIC-IDS2017 feature order
- All 52 features now properly extracted

#### B. Real Data Simulation
- Changed `simulate_attack()` to use real CIC-IDS2017 samples
- Now loads actual attack patterns from dataset
- Model correctly identifies: DDoS, Port Scanning, Brute Force, Web Attacks

#### C. Autoencoder Threshold
- Old threshold: 0.5 (too high, never flagged anomalies)
- New threshold: 0.2 (optimal based on Youden's J statistic analysis)
- Saved to `models/autoencoder_threshold.npy`

#### D. Verdict Logic
- RF says Attack → Attack verdict
- RF says Benign + high confidence → Benign
- RF says Benign + low confidence + AE anomaly → Suspicious (possible zero-day)

#### E. Dashboard Fixes
- Fixed API endpoint paths (`/api/attack-distribution-mapped`)
- Added `/api/timeline` endpoint
- Fixed donut chart rendering
- Fixed gauge calculation
- Added timeline SVG rendering

### 3. New Files Created

| File | Purpose |
|------|---------|
| `dashboard.html` | Custom Flask-based dashboard |
| `test_attack.py` | Windows attack simulation script |
| `README.md` | Project documentation |

### 4. API Endpoints

All endpoints work with the dashboard:
- `/api/stats` - Dashboard metrics
- `/api/alerts` - Recent alerts
- `/api/attack-distribution-mapped` - Mapped for donut chart
- `/api/timeline` - Time-series data
- `/api/top-attackers` - Top attacking IPs
- `/api/simulate` - Run attack simulation

### 5. Testing Results

| Attack Type | Detection |
|------------|-----------|
| DDoS | 100% ✓ |
| Port Scanning | 100% ✓ |
| Brute Force | 100% ✓ |
| Normal Traffic | Correctly identified ✓ |

### 6. Live Capture

- Added `LIVE_CAPTURE=true` environment variable support
- Requires Npcap installed on Windows
- Captures real network packets and analyzes them

### 7. Documentation

Created:
- `README.md` - Complete project documentation
- Updated `AGENTS.md` - Recent changes section

---

**End of Session** - Project is now functional with Flask API, custom dashboard, and attack simulation.
