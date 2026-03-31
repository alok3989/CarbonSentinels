import numpy as np
import time
from sklearn.ensemble import IsolationForest
import logging
import asyncio

logger = logging.getLogger("CarbonSentinel")

history_cache = {}

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.is_trained = False

    def train_model(self, historical_data: list):
        if historical_data:
            self.model.fit(historical_data)
            self.is_trained = True

    def score_transaction(self, volume: float) -> int:
        if not self.is_trained:
            return 50 if volume > 1000 else 10
            
        prediction_score = self.model.decision_function([[volume]])
        normalized_risk = int((1 - prediction_score[0]) * 50) 
        return max(0, min(100, normalized_risk))

anomaly_engine = AnomalyDetector()

def heurist_pattern_match(payload: dict) -> dict:
    corp_id = payload["corporate_id"]
    current_time = time.time()
    
    if corp_id not in history_cache:
        history_cache[corp_id] = []
        
    history = history_cache[corp_id]
    recent_tx = [t for t in history if current_time - t < 300]
    
    if len(recent_tx) > 5:
        logger.warning(f"Velocity pattern triggered for {corp_id}.")
        return {"status": "HALTED", "reason": "Velocity pattern triggered. Excessive claims within 5m window.", "risk_score": 100}
    
    recent_tx.append(current_time)
    history_cache[corp_id] = recent_tx
    
    risk_score = anomaly_engine.score_transaction(payload["volume_tons"])
    return {"status": "PASSED", "risk_score": risk_score}

# Asynchronous background task wrapper 
async def process_transaction_async(payload: dict, db_session, payload_uuid: str):
    from vault import commit_to_ledger
    from models import ProcessedTransaction
    from ws_gateway import socket_manager
    
    logger.info(f"Background worker processing task {payload_uuid}")
    
    # TELEMETRY: Broadcast SCANNING State
    await socket_manager.broadcast_transaction_update({
        "id": payload_uuid, "corporate_id": payload["corporate_id"], 
        "volume_tons": payload["volume_tons"], "status": "SCANNING", "risk_score": 0
    })
    
    # Allow UI effect visualization buffer
    await asyncio.sleep(1)

    # 1. Conflict Zone Analysis
    evaluation = heurist_pattern_match(payload)
    risk_score = evaluation.get("risk_score", 0)

    db_txn = db_session.query(ProcessedTransaction).filter(ProcessedTransaction.id == payload_uuid).first()
    if not db_txn:
        return

    # 2. Vault Layer Crypto Logging
    if evaluation.get("status") == "HALTED" or risk_score > 75:
        db_txn.status = "HALTED"
        db_txn.reason = evaluation.get("reason", "Critical anomaly risk score.")
        db_txn.risk_score = risk_score
    else:
        try:
            tx_hash = await commit_to_ledger(payload)
            db_txn.status = "SECURED"
            db_txn.ledger_hash = tx_hash
            db_txn.risk_score = risk_score
        except Exception as e:
            db_txn.status = "FAILED"
            db_txn.reason = f"Crypto Error: {str(e)}"
    
    db_session.commit()
    logger.info(f"Task {payload_uuid} fully resolved with status {db_txn.status}")

    # FINAL TELEMETRY: Broadcast Absolute Verdict
    await socket_manager.broadcast_transaction_update({
        "id": payload_uuid, "corporate_id": payload["corporate_id"], 
        "volume_tons": payload["volume_tons"], "status": db_txn.status, 
        "risk_score": risk_score, "reason": db_txn.reason
    })
