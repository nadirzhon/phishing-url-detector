import sys, math
sys.path.insert(0, ".")
from detector import extract_features, predict_url, entropy

def test_entropy_calculation():
    # Random string should have higher entropy than repetitive string
    assert entropy("aaaaaaaaaa") < entropy("a1b2c3d4e5")
    assert entropy("") == 0

def test_known_phishing_url():
    result = predict_url("http://paypa1-secure-login.verify-account.xyz/update")
    assert result["is_phishing"] == True
    assert result["risk_score"] >= 40

def test_known_legit_url():
    result = predict_url("https://github.com/nadirzhon")
    assert result["is_phishing"] == False

def test_ip_based_url():
    result = predict_url("http://192.168.1.1/login")
    assert result["features"]["has_ip"] == 1

def test_https_detection():
    features = extract_features("https://example.com")
    assert features["has_https"] == 1
    features2 = extract_features("http://example.com")
    assert features2["has_https"] == 0

def test_brand_keyword_detection():
    features = extract_features("http://paypal-login.evil.com")
    assert features["has_brand_keyword"] == 1

if __name__ == "__main__":
    test_entropy_calculation()
    test_known_phishing_url()
    test_known_legit_url()
    test_ip_based_url()
    test_https_detection()
    test_brand_keyword_detection()
    print("All tests passed.")
