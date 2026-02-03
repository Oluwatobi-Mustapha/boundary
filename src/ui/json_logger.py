import json
import os
import datetime
from dataclasses import asdict
from src.models.request import AccessRequest
from src.core.engine import EvaluationResult

def to_serializable_dict(obj) -> dict:
    """
    Helper to convert dataclasses to dictionaries.
    IMPROVEMENT: Replaces raw float timestamps with human-readable ISO 8601 strings.
    """
    # 1. Get the raw dictionary
    data = asdict(obj)
    
    # 2. List of fields we know are timestamps (Unix Epoch Floats)
    timestamp_fields = ["requested_at", "expires_at", "effective_expires_at"]
    
    # 3. Loop through and REPLACE them with ISO strings
    for field in timestamp_fields:
        val = data.get(field)
        # Check if value exists, is a number, and is not 0.0
        if val and isinstance(val, (int, float)) and val > 0:
            # Overwrite the float with the string
            data[field] = datetime.datetime.fromtimestamp(val, datetime.timezone.utc).isoformat()
            
    return data

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
        "schema_version": "1.1", 
        "timestamp": res.evaluated_at,
        "correlation_id": req.request_id,
        # Req 3: Integrity Metadata
        "engine_metadata": {
            "version": getattr(res, "engine_version", "unknown"),
            "policy_hash": getattr(res, "policy_hash", "unknown"),
            "rules_processed": getattr(res, "rules_processed", 0)
        },
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