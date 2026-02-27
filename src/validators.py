"""
Input validation utilities for security-critical parameters.
Prevents injection attacks, DoS, and enumeration vulnerabilities.
"""
import re
import math


def validate_duration(duration: float) -> float:
    """
    Validates requested access duration.
    
    Args:
        duration: Requested duration in hours
        
    Returns:
        Validated duration
        
    Raises:
        ValueError: If duration is invalid
    """
    if math.isnan(duration) or math.isinf(duration):
        raise ValueError(f"Duration must be a valid number, got: {duration}")
    
    if duration <= 0:
        raise ValueError(f"Duration must be positive, got: {duration}")
    
    if duration > 720:  # Max 30 days
        raise ValueError(f"Duration exceeds maximum of 720 hours (30 days), got: {duration}")
    
    return duration


def validate_account_id(account_id: str) -> str:
    """
    Validates AWS Account ID format.
    
    Args:
        account_id: AWS 12-digit account ID
        
    Returns:
        Validated account ID
        
    Raises:
        ValueError: If account ID format is invalid
    """
    if not account_id:
        raise ValueError("Account ID cannot be empty")
    
    if not re.match(r'^\d{12}$', account_id):
        raise ValueError(f"Invalid AWS Account ID format. Expected 12 digits, got: {account_id}")
    
    return account_id


REQUEST_ID_PATTERN = re.compile(r'^req-[a-f0-9]{16}$')


def validate_request_id(request_id: str) -> str:
    """
    Validates that a request ID matches the expected format: req-<16 hex chars>.

    Args:
        request_id: The request ID to validate

    Returns:
        Validated request ID

    Raises:
        ValueError: If request ID format is invalid
    """
    if not request_id:
        raise ValueError("Request ID cannot be empty")

    if not REQUEST_ID_PATTERN.match(request_id):
        raise ValueError(
            f"Invalid request ID format. Expected 'req-' followed by "
            f"16 hex characters, got: {request_id}"
        )

    return request_id


def validate_arn(arn: str, resource_type: str | None = None) -> str:
    """
    Validates AWS ARN format.
    
    Args:
        arn: AWS ARN string
        resource_type: Optional resource type to validate (e.g., 'sso', 'iam')
        
    Returns:
        Validated ARN
        
    Raises:
        ValueError: If ARN format is invalid
    """
    if not arn:
        raise ValueError("ARN cannot be empty")
    
    # Support only valid AWS partitions: aws, aws-cn, aws-us-gov
    if not re.match(r'^arn:aws(-cn|-us-gov)?:', arn):
        raise ValueError(f"Invalid ARN format. Must start with 'arn:aws:', 'arn:aws-cn:', or 'arn:aws-us-gov:', got: {arn}")
    
    parts = arn.split(":")
    if len(parts) < 6:
        raise ValueError(f"Invalid ARN format. Expected at least 6 parts, got: {len(parts)}")
    
    if resource_type and parts[2] != resource_type:
        raise ValueError(f"Expected ARN for {resource_type}, got: {parts[2]}")
    
    return arn
