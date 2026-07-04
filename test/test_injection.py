import pandas as pd
import requests

df = pd.read_csv(
    "dataset/CICIOT23/test/test.csv"
)

sample = df.iloc[0]

features = sample.drop(
    "label"
).tolist()

packet_window = [
    features,
    features,
    features,
    features,
    features
]

payload = {
    "packet_window": packet_window
}

response = requests.post(
    "http://localhost:5001/scan",
    json=payload
)

print("\nStatus Code:")
print(response.status_code)

print("\nResponse:")
print(response.text)

print("\nActual Label:")
print(sample["label"])