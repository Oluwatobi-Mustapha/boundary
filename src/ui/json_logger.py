import json
import os
from dataclasses import asdict
from src.models.request import AccessRequest
from src.core.engine import EvaluationResult

def to_serializable_dict(obj) -> dict:
    """Helper to convert dataclasses to dictionaries."""
    return asdict(obj)

def log_audit_event(req: AccessRequest, res: EvaluationResult, output_dir="audit_logs") -> str:
    """
    Writes the full decision context to a durable JSON file.
    Returns the filepath of the created artifact.
    """
    # 1. Ensure the audit directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 2. Construct the Log Entry (The "Single Source of Truth")
    log_entry = {
        "schema_version": "1.0",
        "timestamp": res.evaluated_at,  # Req 3: ISO 8601
        "correlation_id": req.request_id, # Req 3: Correlation ID
        "request": to_serializable_dict(req),
        "result": to_serializable_dict(res)
    }

    # 3. Generate a deterministic filename
    # Format: audit_logs/2026-02-03_req-12345.json
    filename = f"{req.requested_at}_{req.request_id}.json"
    filepath = os.path.join(output_dir, filename)

    # 4. Write to disk (Req 8: Durable Artifact)
    with open(filepath, 'w') as f:
        json.dump(log_entry, f, indent=2)
        
    return filepath