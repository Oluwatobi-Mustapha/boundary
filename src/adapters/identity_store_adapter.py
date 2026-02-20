import boto3
import botocore.exceptions
import logging
import time
import re
import random
from collections import OrderedDict
from typing import Tuple

logger = logging.getLogger(__name__)

class IdentityStoreError(Exception):
    """Base exception for Identity Store errors."""
    pass

class IdentityStoreAdapter:
    def __init__(self, identity_store_id: str, cache_max_size: int = 1000, cache_ttl_seconds: int = 300):
        """
        Initializes the Identity Store Adapter.
        Requires the AWS SSO Identity Store ID (e.g., d-1234567890).
        
        Args:
            identity_store_id: AWS Identity Store ID
            cache_max_size: Maximum number of entries to cache (default 1000)
            cache_ttl_seconds: Time-to-live for cache entries in seconds (default 300 = 5 minutes)
        """
        if not identity_store_id or not identity_store_id.startswith("d-"):
            raise ValueError("A valid Identity Store ID (d-...) is required.")
        
        if cache_max_size <= 0:
            raise ValueError(f"cache_max_size must be positive, got {cache_max_size}")
        
        if cache_ttl_seconds <= 0:
            raise ValueError(f"cache_ttl_seconds must be positive, got {cache_ttl_seconds}")
            
        self.identity_store_id = identity_store_id
        self.client = boto3.client('identitystore')
        
        # LRU cache with bounded size and TTL to prevent memory leak and stale data
        self._user_cache: OrderedDict[str, Tuple[str, float]] = OrderedDict()
        self._cache_max_size = cache_max_size
        self._cache_ttl_seconds = cache_ttl_seconds
    
    def __repr__(self):
        return f"IdentityStoreAdapter(store_id={self.identity_store_id})"

    def get_user_id_by_email(self, email: str, max_retries: int = 3) -> str:
        """
        Queries AWS Identity Store to translate an email address 
        into an immutable AWS User ID (UUID).
        """
        # Validate email format
        if not email or not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            raise ValueError(f"Invalid email address format: {email}")

        # Check cache first
        if email in self._user_cache:
            user_id, cached_at = self._user_cache[email]
            age = time.time() - cached_at
            
            # Check if cache entry has expired (TTL)
            if age < self._cache_ttl_seconds:
                logger.debug("Cache hit for Identity Store lookup")
                # Move to end (mark as recently used)
                self._user_cache.move_to_end(email)
                return user_id
            else:
                # Cache entry expired, remove it
                logger.debug(f"Cache entry expired (age: {age:.1f}s, TTL: {self._cache_ttl_seconds}s)")
                self._user_cache.pop(email)

        for attempt in range(1, max_retries + 1):
            try:
                # Query AWS Identity Store
                response = self.client.get_user_id(
                    IdentityStoreId=self.identity_store_id,
                    AlternateIdentifier={
                        'UniqueAttribute': {
                            'AttributePath': 'emails.value',
                            'AttributeValue': email
                        }
                    }
                )
                
                user_id = response['UserId']
                
                # Add to cache with LRU eviction and TTL
                if len(self._user_cache) >= self._cache_max_size:
                    # Remove oldest entry (FIFO/LRU)
                    evicted_email = next(iter(self._user_cache))
                    self._user_cache.pop(evicted_email)
                    logger.debug("Cache full, evicted entry")
                
                # Store user_id with timestamp for TTL validation
                self._user_cache[email] = (user_id, time.time())
                # Successfully resolved identity without logging PII
                logger.debug("Successfully resolved email to AWS User ID")
                return user_id
                
            except self.client.exceptions.ResourceNotFoundException:
                logger.error("User not found in Identity Store")
                logger.debug(f"Email not found: {email}")
                raise IdentityStoreError(f"Email '{email}' is not registered in AWS Identity Center")
            
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                
                if error_code == 'ThrottlingException':
                    # AWS is rate limiting us
                    if attempt == max_retries:
                        logger.error("Throttled on final attempt")
                        raise IdentityStoreError("AWS throttling exceeded max retries")
                    
                    # Exponential backoff with jitter to prevent thundering herd
                    backoff = 2 ** (attempt - 1)
                    jitter = random.uniform(0, backoff * 0.5)  # AWS recommended: 0-50% jitter
                    sleep_time = backoff + jitter
                    
                    logger.warning(
                        f"AWS throttling (ThrottlingException). "
                        f"Waiting {sleep_time:.2f} seconds... (Attempt {attempt}/{max_retries})"
                    )
                    time.sleep(sleep_time)
                    continue
                else:
                    logger.error(f"AWS API error: {error_code}")
                    logger.debug(f"AWS API error for email {email}: {error_code} - {e}")
                    raise IdentityStoreError(f"AWS Identity Store error: {error_code}")
            
            except Exception as e:
                logger.error(f"Unexpected error querying Identity Store: {type(e).__name__}")
                raise IdentityStoreError(f"Failed to query Identity Store: {type(e).__name__}")

        # If we exit the loop, we exhausted all retries
        logger.error(f"Failed to fetch user ID after {max_retries} retries")
        raise IdentityStoreError("Identity Store query exceeded max retries")
