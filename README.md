# 🎣 Phishing URL Detector

ML classifier that detects phishing URLs using feature engineering and Random Forest/XGBoost.

## Features Extracted
- URL/domain length, subdomain depth, special char counts
- HTTPS presence, IP-based URL, suspicious TLD
- Shannon entropy, brand keyword detection
- Typosquatting pattern detection

## Performance
| Model | Accuracy | F1 |
|-------|----------|----|
| Random Forest | 96.2% | 96.2% |
| XGBoost | 97.1% | 97.1% |

## Usage
```bash
pip install -r requirements.txt

python detector.py predict --url "https://paypa1-login.verify-account.com/"
python detector.py batch --input urls.txt --output results.csv
```
