import requests
import time


API_URL = "http://127.0.0.1:8000/predict"


benign_features = {
    "files_created": 2,
    "files_modified": 1,
    "files_deleted": 0,
    "files_renamed": 0,
    "writes_per_second": 1.5,
    "unique_extensions": 2,
    "unique_directories": 2,
    "extension_change_count": 0,
    "rename_ratio": 0.0,
    "mean_entropy": 0.45,
    "entropy_change": 0.01
}


attack_features = {
    "files_created": 5,
    "files_modified": 80,
    "files_deleted": 2,
    "files_renamed": 35,
    "writes_per_second": 45.0,
    "unique_extensions": 8,
    "unique_directories": 12,
    "extension_change_count": 7,
    "rename_ratio": 0.82,
    "mean_entropy": 0.91,
    "entropy_change": 0.35
}


for i in range(10):

    if i < 5:
        features = benign_features
        activity = "BENIGN"
    else:
        features = attack_features
        activity = "ATTACK-LIKE"

    response = requests.post(
        API_URL,
        json=features
    )

    result = response.json()

    print("=" * 50)
    print(f"Window: {i + 1}")
    print(f"Simulated activity: {activity}")
    print(f"Prediction: {result['prediction']}")
    print(f"Severity: {result['severity']}")
    print(f"Threat score: {result['threat_score']}")
    print("=" * 50)

    time.sleep(2)