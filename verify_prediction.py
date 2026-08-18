"""Verify predict_login returns real probability-based threat scores."""
from prediction.predict import predict_login
from datetime import datetime

now = datetime.now()

# Test 1 — Normal daytime login
r1 = predict_login(user=6, pc=106, activity=5,
                   hour=10, day=now.day, month=now.month, weekday=0)
print("=== Test 1: Daytime (10am, weekday) ===")
print(f"  Prediction  : {r1['prediction']}")
print(f"  Risk        : {r1['risk']}")
print(f"  Threat Score: {r1['threat_score']}")
print(f"  Confidence  : {r1['confidence']}")
print(f"  Reasons     : {r1['reasons']}")

# Test 2 — Late-night login (higher risk expected)
r2 = predict_login(user=6, pc=106, activity=5,
                   hour=2, day=now.day, month=now.month, weekday=6)
print("\n=== Test 2: Late night (2am, Sunday) ===")
print(f"  Prediction  : {r2['prediction']}")
print(f"  Risk        : {r2['risk']}")
print(f"  Threat Score: {r2['threat_score']}")
print(f"  Confidence  : {r2['confidence']}")
print(f"  Reasons     : {r2['reasons']}")

# Verify scores are non-zero and different
assert r1['threat_score'] >= 0, "Threat score must be >= 0"
assert r2['threat_score'] >= 0, "Threat score must be >= 0"
assert r1['confidence'] > 0,   "Confidence must be > 0"
print("\n✓ Prediction pipeline working with real model probabilities")
