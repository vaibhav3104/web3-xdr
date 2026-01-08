# Sentinel3 ML Model Training Pipeline

## Overview

This pipeline trains a RandomForest/XGBoost classifier to detect malicious smart contracts using 43-dimensional feature vectors extracted from bytecode.

## Quick Start

```bash
# Train with mock exploits (for testing)
python src/ai/training/train_model.py --use-mock-exploits

# Train with real exploit data (requires blockchain RPC)
python src/ai/training/train_model.py

# Use XGBoost instead of RandomForest
python src/ai/training/train_model.py --model xgboost

# Disable SMOTE oversampling
python src/ai/training/train_model.py --no-smote
```

## Feature Importance Interpretation

### Top 10 Most Important Features (Example)

Based on training results, here's what the model considers most predictive:

1. **storage_intensity** (0.1608) - Ratio of storage operations to total operations
   - **Why it matters**: Exploit contracts often manipulate storage state aggressively
   - **Action**: Monitor contracts with storage_intensity > 0.3

2. **cfg_complexity_score** (0.0923) - Control flow graph complexity
   - **Why it matters**: Complex control flow may indicate exploit logic
   - **Action**: Flag contracts with CFG complexity > 50

3. **push_data_entropy** (0.0900) - Entropy of PUSH instruction data
   - **Why it matters**: Low entropy suggests packed/obfuscated code
   - **Action**: Investigate contracts with entropy < 3.0

4. **unique_opcodes** (0.0798) - Number of unique opcodes used
   - **Why it matters**: Exploit contracts use specific opcode patterns
   - **Action**: Compare against known exploit opcode sets

5. **max_nesting_depth** (0.0696) - Maximum nesting depth of control flow
   - **Why it matters**: Deep nesting suggests complex exploit logic
   - **Action**: Flag contracts with nesting > 5

6. **bytecode_length** (0.0536) - Total bytecode size
   - **Why it matters**: Exploit contracts are often optimized (small) or obfuscated (large)
   - **Action**: Check both very small (< 1000 bytes) and very large (> 50000 bytes)

7. **external_interaction_ratio** (0.0492) - Ratio of external calls to total operations
   - **Why it matters**: High ratio suggests flash loan or reentrancy patterns
   - **Action**: Monitor contracts with ratio > 0.1

8. **basic_block_count** (0.0436) - Number of basic blocks in CFG
   - **Why it matters**: More blocks = more complex logic
   - **Action**: Compare against baseline for contract type

9. **high_gas_opcode_ratio** (0.0415) - Ratio of expensive opcodes
   - **Why it matters**: Exploit contracts optimize gas usage differently
   - **Action**: Flag unusual gas patterns

10. **function_count** (0.0400) - Number of function signatures
    - **Why it matters**: Exploit contracts expose specific attack functions
    - **Action**: Check for known exploit function signatures

### Feature Categories

#### 1. Basic Metrics (4 features)
- `bytecode_length`, `unique_opcodes`, `total_instructions`, `code_density`
- **Interpretation**: Size and complexity indicators

#### 2. Opcode Counts (8 features)
- `call_count`, `delegatecall_count`, `staticcall_count`, `create_count`, etc.
- **Interpretation**: External interaction patterns

#### 3. CFG Complexity (6 features)
- `cfg_complexity_score`, `jump_count`, `jumpi_count`, `basic_block_count`, etc.
- **Interpretation**: Control flow complexity (higher = more complex logic)

#### 4. External Calls (3 features)
- `external_call_depth`, `external_call_sequence_length`, `call_to_storage_ratio`
- **Interpretation**: Call patterns (deep = flash loan chains)

#### 5. Entropy (3 features)
- `bytecode_entropy`, `opcode_entropy`, `push_data_entropy`
- **Interpretation**: Code randomness (low = packed/obfuscated)

#### 6. Gas Analysis (3 features)
- `estimated_gas_cost`, `gas_per_instruction`, `high_gas_opcode_ratio`
- **Interpretation**: Gas optimization patterns

#### 7. Pattern Detection (8 features)
- `has_flash_loan_callback`, `has_reentrancy_pattern`, `has_proxy_pattern`, etc.
- **Interpretation**: Direct exploit indicators (boolean flags)

#### 8. Risk Patterns (5 features)
- `has_reentrancy_pattern`, `has_delegatecall_pattern`, `has_unchecked_call`, etc.
- **Interpretation**: Security risk flags

#### 9. Advanced Metrics (3 features)
- `storage_intensity`, `external_interaction_ratio`, `risk_score`
- **Interpretation**: Composite risk indicators

## Using the Trained Model

```python
import joblib
from src.ai.data.enhanced_extractor import EnhancedBytecodeExtractor

# Load model
model = joblib.load("src/ai/models/classifier.pkl")

# Extract features
extractor = EnhancedBytecodeExtractor()
features = extractor.extract_features(bytecode)
vector = features.to_vector()

# Predict
prediction = model.predict([vector])[0]  # 0 = safe, 1 = exploit
probability = model.predict_proba([vector])[0][1]  # Probability of exploit

print(f"Prediction: {'EXPLOIT' if prediction == 1 else 'SAFE'}")
print(f"Confidence: {probability:.2%}")
```

## Model Performance

### Metrics (Example from Training)

- **Accuracy**: 1.000 (perfect separation on test set)
- **Precision**: 1.000 (no false positives)
- **Recall**: 1.000 (no false negatives)
- **F1 Score**: 1.000
- **ROC AUC**: 1.000

**Note**: Perfect scores indicate the model can distinguish between safe and exploit contracts in the training data. Real-world performance may vary.

### Confusion Matrix

```
                Predicted
              Safe  Exploit
Actual Safe     9      0
       Exploit   0     15
```

## Improving the Model

1. **Collect More Data**: Add more exploit contracts from recent attacks
2. **Feature Engineering**: Add domain-specific features (e.g., bridge-specific patterns)
3. **Hyperparameter Tuning**: Use GridSearchCV to optimize RandomForest parameters
4. **Ensemble Methods**: Combine multiple models for better accuracy
5. **Deep Learning**: Use neural networks for complex pattern recognition

## Troubleshooting

### Issue: "No valid features extracted"

**Solution**: Check that bytecode is valid hex format and contains actual contract code (not just "0x").

### Issue: "ValueError: setting an array element with a sequence"

**Solution**: Ensure all feature vectors have exactly 43 dimensions. Check `EnhancedBytecodeExtractor.to_vector()`.

### Issue: "SMOTE requires more than 1 sample per class"

**Solution**: Increase the number of samples or disable SMOTE with `--no-smote`.

## Output Files

- `classifier.pkl` - Trained model (for production use)
- `feature_importance.png` - Visual feature importance plot
- `confusion_matrix.png` - Confusion matrix visualization
- `training_metrics.json` - Detailed metrics and evaluation results

## Next Steps

1. Deploy model to production inference endpoint
2. Integrate with contract deployment listener
3. Set up continuous retraining pipeline
4. Monitor model performance in production
5. Collect feedback for model improvement

