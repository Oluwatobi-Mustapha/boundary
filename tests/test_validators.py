"""
Unit tests for input validation (Security Fixes H-2, H-3)
"""
import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.validators import validate_duration, validate_account_id, validate_arn


class TestDurationValidation:
    """Tests for H-2: Duration validation"""
    
    def test_valid_duration(self):
        assert validate_duration(1.0) == 1.0
        assert validate_duration(8.5) == 8.5
        assert validate_duration(720.0) == 720.0
    
    def test_negative_duration_rejected(self):
        with pytest.raises(ValueError, match="must be positive"):
            validate_duration(-1.0)
    
    def test_zero_duration_rejected(self):
        with pytest.raises(ValueError, match="must be positive"):
            validate_duration(0.0)
    
    def test_excessive_duration_rejected(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_duration(721.0)
        
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_duration(999999.0)
    
    def test_nan_duration_rejected(self):
        """P1 Fix: NaN bypasses validation"""
        with pytest.raises(ValueError, match="must be a valid number"):
            validate_duration(float('nan'))
    
    def test_infinity_duration_rejected(self):
        """P1 Fix: Infinity bypasses validation"""
        with pytest.raises(ValueError, match="must be a valid number"):
            validate_duration(float('inf'))
        
        with pytest.raises(ValueError, match="must be a valid number"):
            validate_duration(float('-inf'))


class TestAccountIDValidation:
    """Tests for H-3: Account ID validation"""
    
    def test_valid_account_id(self):
        assert validate_account_id("123456789012") == "123456789012"
        assert validate_account_id("000000000000") == "000000000000"
    
    def test_empty_account_id_rejected(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_account_id("")
    
    def test_short_account_id_rejected(self):
        with pytest.raises(ValueError, match="Invalid AWS Account ID"):
            validate_account_id("12345")
    
    def test_long_account_id_rejected(self):
        with pytest.raises(ValueError, match="Invalid AWS Account ID"):
            validate_account_id("1234567890123")
    
    def test_non_numeric_account_id_rejected(self):
        with pytest.raises(ValueError, match="Invalid AWS Account ID"):
            validate_account_id("12345678901a")
    
    def test_sql_injection_attempt_rejected(self):
        with pytest.raises(ValueError, match="Invalid AWS Account ID"):
            validate_account_id("'; DROP TABLE--")


class TestARNValidation:
    """Tests for ARN validation"""
    
    def test_valid_arn(self):
        arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        assert validate_arn(arn) == arn
    
    def test_valid_govcloud_arn(self):
        """P2 Fix: GovCloud ARNs should be accepted"""
        arn = "arn:aws-us-gov:sso:::instance/ssoins-123"
        assert validate_arn(arn) == arn
    
    def test_valid_china_arn(self):
        """P2 Fix: China partition ARNs should be accepted"""
        arn = "arn:aws-cn:sso:::instance/ssoins-123"
        assert validate_arn(arn) == arn
    
    def test_empty_arn_rejected(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_arn("")
    
    def test_invalid_arn_prefix_rejected(self):
        with pytest.raises(ValueError, match="Must start with"):
            validate_arn("invalid:arn:format")
    
    def test_malformed_arn_rejected(self):
        with pytest.raises(ValueError, match="Expected at least 6 parts"):
            validate_arn("arn:aws:sso")
    
    def test_resource_type_validation(self):
        sso_arn = "arn:aws:sso:::instance/ssoins-123"
        assert validate_arn(sso_arn, "sso") == sso_arn
        
        with pytest.raises(ValueError, match="Expected ARN for iam"):
            validate_arn(sso_arn, "iam")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
