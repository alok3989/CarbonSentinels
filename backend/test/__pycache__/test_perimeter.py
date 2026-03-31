import pytest
from fastapi.testclient import TestClient
import json
import jwt
from main import app

# Local mock authentication
SECRET = "super-secret-signature-key-replace-in-production"
MOCK_TOKEN = jwt.encode({"corporate_id": "CORP-TEST", "role": "verifier"}, SECRET, algorithm="HS256")
AUTH_HEADER = {"Authorization": f"Bearer {MOCK_TOKEN}"}

client = TestClient(app)

def test_health_check_perimeter():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "OMNI_DEFENSE_ACTIVE"

def test_jwt_perimeter_unauthorized_rejection():
    # Sending valid payload but strictly missing the JWT token Authorization
    payload = {
        "corporate_id": "CORP-111",
        "asset_id": "ASSET-B",
        "volume_tons": 500,
        "zk_proof_data": {
            "proof": "0xABC123",
            "public_signals": ["0x999"]
        }
    }
    response = client.post("/api/v2/transaction/submit", json=payload)
    
    # Assert Strict 401 Rejection natively mapping from the JWT Guard dependency
    assert response.status_code == 401
    assert "Missing or invalid" in response.json()["detail"]

def test_pydantic_nosql_lexical_pollution_prevention():
    # Hacker tries to pass $where clause mapping MongoDB injection logic inside the zk parameters
    malicious_payload = {
        "corporate_id": "CORP-111",
        "asset_id": "ASSET-B",
        "volume_tons": 500,
        "zk_proof_data": {
            "proof": "0xABC123",
            "public_signals": ["$where: 'sleep(100)'"]
        }
    }
    
    response = client.post("/api/v2/transaction/submit", headers=AUTH_HEADER, json=malicious_payload)
    
    # Assert Fast Request Rejection natively mapping from our strict before-mode validator
    assert response.status_code == 422
    assert "Lexical Violation" in str(response.json())
    assert "$where" in str(response.json())
