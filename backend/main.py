import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
import logging
import uuid
import jwt

# Load environment logic heavily
load_dotenv()

from database import engine, Base, get_db
from models import ProcessedTransaction
from perimeter_defense import app, TransactionPayload, rate_limit_and_ban_check, verify_jwt
from conflict_zone import process_transaction_async
from ws_gateway import ws_router, socket_manager

# Mount WebSocket Gateway Extension
app.include_router(ws_router)

# Create persistent DB Tables
Base.metadata.create_all(bind=engine)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CarbonSentinel")

@app.get("/")
def health_check():
    return {"status": "OMNI_DEFENSE_ACTIVE", "service": "CarbonSentinel Core Engine V3"}

# Phase 3 - Broadcast Hooks enabled 
@app.post("/api/v2/transaction/submit", status_code=202, dependencies=[Depends(rate_limit_and_ban_check), Depends(verify_jwt)])
async def submit_transaction(
    payload: TransactionPayload, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    logger.info(f"Layer 1 Cleared: Payload ingress verified.")
    generated_uuid = str(uuid.uuid4())
    
    db_txn = ProcessedTransaction(
        id=generated_uuid,
        corporate_id=payload.corporate_id,
        asset_id=payload.asset_id,
        volume_tons=payload.volume_tons,
        status="PENDING"
    )
    db.add(db_txn)
    db.commit()

    # Initial state broadcast to frontend UI (Circuit Breaker starts here)
    await socket_manager.broadcast_transaction_update({
        "id": generated_uuid, 
        "corporate_id": payload.corporate_id, 
        "volume_tons": payload.volume_tons,
        "status": "PENDING", 
        "risk_score": 0
    })

    background_tasks.add_task(process_transaction_async, payload.model_dump(), db, generated_uuid)

    return {
        "status": "ACCEPTED_FOR_PROCESSING",
        "polling_id": generated_uuid,
        "message": "Payload safely passed to telemetry streams."
    }

@app.get("/api/v2/transaction/{polling_id}", dependencies=[Depends(verify_jwt)])
def check_transaction_status(polling_id: str, db: Session = Depends(get_db)):
    db_txn = db.query(ProcessedTransaction).filter(ProcessedTransaction.id == polling_id).first()
    if not db_txn:
        raise HTTPException(status_code=404, detail="Transaction ID not found.")
        
    return {
        "polling_id": db_txn.id,
        "status": db_txn.status,
        "risk_score": db_txn.risk_score,
        "ledger_hash": db_txn.ledger_hash,
        "reason": db_txn.reason
    }

@app.post("/api/v2/debug/generate-token")
def generate_sample_token(corporate_id: str):
    secret = os.getenv("JWT_SECRET", "super-secret-signature-key-replace-in-production")
    token = jwt.encode({"corporate_id": corporate_id, "role": "verifier"}, secret, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/v2/debug/flood")
async def simulate_flood_attack():
    """Operator Override: Simulates a live NoSQL/Velocity attack storm"""
    import time
    for i in range(5):
        malicious_id = str(uuid.uuid4())
        await socket_manager.broadcast_transaction_update({
            "id": malicious_id, 
            "corporate_id": "ROGUE-NODE-999", 
            "volume_tons": 50000, # Massive anomaly
            "status": "HALTED", 
            "risk_score": 100,
            "reason": "NETWORK_FLOOD_DETECTED"
        })
    return {"status": "FLOOD_DEPLOYED"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
