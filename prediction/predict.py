import joblib
import pandas as pd

# Load the trained model only once
model = joblib.load("models/random_forest_model.pkl")


def predict_login(user, pc, activity, hour, day, month, weekday):
    """
    Predict whether a login is Normal or Suspicious.
    """

    # Working hours (8 AM to 6 PM)
    working_hours = 1 if 8 <= hour <= 18 else 0

    # Weekend
    weekend = 1 if weekday >= 5 else 0

    # Create dataframe
    data = pd.DataFrame({
        "user": [user],
        "pc": [pc],
        "activity": [activity],
        "hour": [hour],
        "day": [day],
        "month": [month],
        "weekday": [weekday],
        "working_hours": [working_hours],
        "weekend": [weekend]
    })

    prediction = model.predict(data)[0]

    if prediction == 1:
        risk = "HIGH"
        result = "Suspicious Login"

        reasons = []

        if hour < 6 or hour > 22:
            reasons.append("Login outside working hours")

        if weekend:
            reasons.append("Weekend Login")

        if len(reasons) == 0:
            reasons.append("Abnormal login behaviour")

    else:
        risk = "LOW"
        result = "Normal Login"
        reasons = ["No suspicious behaviour detected"]

    return {
        "prediction": result,
        "risk": risk,
        "reasons": reasons
    }