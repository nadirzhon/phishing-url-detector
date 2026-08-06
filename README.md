# 🎣 Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green) ![Tests](https://img.shields.io/badge/tests-passing-success) ![Status](https://img.shields.io/badge/status-active-brightgreen)

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

## Responsible use

This project is published for **defensive research, education, and authorized security testing only**.
Use it exclusively on systems you own or have explicit written permission to assess. The author
assumes no liability for misuse. See `SECURITY.md` for the disclosure policy.
