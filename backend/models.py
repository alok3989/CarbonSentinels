from sqlalchemy import Column, String, Float, Integer, DateTime, Index
from database import Base
import datetime
import uuid

class ProcessedTransaction(Base):
    __tablename__ = "vault_transactions"

    # UUID Primary Key (PostgreSQL optimized)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Indexed Wallet/Corporate tracker
    corporate_id = Column(String(255), nullable=False)
    asset_id = Column(String(255), nullable=False)
    volume_tons = Column(Float, nullable=False)
    
    # ML Scoring and Deterministic States
    risk_score = Column(Integer, nullable=True) # 0-100
    status = Column(String(50), nullable=False) # e.g. PENDING, SCANNING, SECURED, HALTED
    reason = Column(String(500), nullable=True) # NLP reason or Cryptographic failure
    
    # Ledger Hash Commit mapping
    ledger_hash = Column(String(255), nullable=True)
    
    # Indexed time-series analog
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# Compound Index targeting high-frequency read queries from the Dashboard UI
Index('idx_wallet_time', ProcessedTransaction.corporate_id, ProcessedTransaction.created_at)
