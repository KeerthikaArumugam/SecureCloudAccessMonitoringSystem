from prediction.predict import predict_login

result = predict_login(
    user=707,
    pc=589,
    activity=1,
    hour=23,
    day=15,
    month=7,
    weekday=6
)

print(result)