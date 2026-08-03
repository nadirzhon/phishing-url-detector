#!/usr/bin/env python3
"""
Phishing URL Detector - ML-based classifier
Author: nadirzhon | github.com/nadirzhon
"""

import argparse
import re
import math
import tldextract
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".site", ".online", ".icu"}
BRAND_KEYWORDS = ["paypal", "apple", "google", "microsoft", "amazon", "facebook",
                  "netflix", "instagram", "whatsapp", "bank", "secure", "login",
                  "verify", "account", "update", "confirm"]

def entropy(s):
    if not s:
        return 0
    p = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(x * math.log2(x) for x in p if x > 0)

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    return {
        "url_length": len(url),
        "domain_length": len(ext.domain),
        "subdomain_depth": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "has_https": int(parsed.scheme == "https"),
        "has_ip": int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc))),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "has_suspicious_tld": int(f".{ext.suffix}" in SUSPICIOUS_TLDS),
        "url_entropy": entropy(url),
        "has_brand_keyword": int(any(kw in url.lower() for kw in BRAND_KEYWORDS)),
        "hex_encoding": int("%2" in url or "%3" in url),
        "query_length": len(parsed.query),
    }

def predict_url(url):
    features = extract_features(url)
    score = 0
    if features["has_ip"]:                                      score += 30
    if features["has_brand_keyword"] and not features["has_https"]: score += 25
    if features["url_length"] > 100:                            score += 15
    if features["subdomain_depth"] > 3:                         score += 20
    if features["has_suspicious_tld"]:                          score += 20
    if features["url_entropy"] > 4.5:                           score += 10
    if features["num_hyphens"] > 5:                             score += 10

    return {"url": url, "is_phishing": score >= 40,
            "risk_score": score, "features": features}

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("predict")
    p.add_argument("--url", required=True)
    b = sub.add_parser("batch")
    b.add_argument("--input", required=True)
    b.add_argument("--output")
    args = parser.parse_args()

    if args.command == "predict":
        r = predict_url(args.url)
        label = f"{Fore.RED}PHISHING" if r["is_phishing"] else f"{Fore.GREEN}LEGITIMATE"
        print(f"\n  URL: {r['url']}")
        print(f"  Verdict: {label}{Style.RESET_ALL}")
        print(f"  Risk Score: {r['risk_score']}/100")

    elif args.command == "batch":
        results = []
        with open(args.input) as f:
            for line in f:
                url = line.strip()
                if url:
                    r = predict_url(url)
                    results.append(r)
                    color = Fore.RED if r["is_phishing"] else Fore.GREEN
                    verdict = "PHISHING" if r["is_phishing"] else "OK"
                    print(f"  {color}[{verdict}]{Style.RESET_ALL} {url}")
        if args.output:
            import csv
            with open(args.output, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["url","is_phishing","risk_score"])
                w.writeheader()
                for r in results:
                    w.writerow({"url": r["url"], "is_phishing": r["is_phishing"],
                                "risk_score": r["risk_score"]})
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
