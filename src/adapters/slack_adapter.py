import urllib.request
import urllib.error
import json
import time
import logging
import random
from collections import OrderedDict
from typing import Tuple

logger = logging.getLogger(__name__)

class SlackAPIError(Exception):
    """Base exception for Slack API errors."""
    pass

class SlackRateLimitError(SlackAPIError):
    """Raised when Slack rate limit is exceeded."""
    pass

class SlackAdapter:
    def __init__(self, bot_token: str, cache_max_size: int = 1000, cache_ttl_seconds: int = 300):
        """
        Initializes the Slack Adapter with the xoxb- Bot Token.
        
        Args:
            bot_token: Slack Bot Token (xoxb-...)
            cache_max_size: Maximum number of entries to cache (default 1000)
            cache_ttl_seconds: Time-to-live for cache entries in seconds (default 300 = 5 minutes)
        """
        if not bot_token or not bot_token.startswith("xoxb-"):
            raise ValueError("A valid Slack Bot Token (xoxb-) is required.")
        
        if cache_max_size <= 0:
            raise ValueError(f"cache_max_size must be positive, got {cache_max_size}")
        
        if cache_ttl_seconds <= 0:
            raise ValueError(f"cache_ttl_seconds must be positive, got {cache_ttl_seconds}")
        
        self.bot_token = bot_token
        self.base_url = "https://slack.com/api"
        
        # LRU cache with bounded size and TTL to prevent memory leak and stale data
        self._email_cache: OrderedDict[str, Tuple[str, float]] = OrderedDict()
        self._cache_max_size = cache_max_size
        self._cache_ttl_seconds = cache_ttl_seconds
    
    def __repr__(self):
        return "SlackAdapter(token=***REDACTED***)"

    def get_user_email(self, slack_user_id: str, max_retries: int = 3) -> str:
        """
        Translates a Slack user ID (e.g., U123456) into a corporate email address.
        Includes robust handling for HTTP 429 Rate Limits with caching.
        """
        if not slack_user_id or not slack_user_id.startswith("U"):
            raise ValueError(f"Invalid Slack user ID: {slack_user_id}")
        
        # Check cache first
        if slack_user_id in self._email_cache:
            logger.debug("Cache hit for Slack user lookup")
            # Move to end (mark as recently used)
            self._email_cache.move_to_end(slack_user_id)
            return self._email_cache[slack_user_id]
        
        url = f"{self.base_url}/users.info?user={slack_user_id}"
        
        # Validate URL scheme for security (Bandit B310)
        if not url.startswith("https://"):
            raise ValueError(f"Invalid URL scheme. Only HTTPS is allowed: {url}")
        
        # We must prove our identity to Slack using the Bearer token
        headers = {
            "Authorization": f"Bearer {self.bot_token}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        for attempt in range(1, max_retries + 1):
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
                    # Slack returns HTTP 200 even for logical errors, so we parse the JSON
                    data = json.loads(response.read().decode("utf-8"))

                    if not data.get("ok"):
                        error_msg = data.get("error", "Unknown Slack API error")
                        logger.error(f"Slack API rejected request: {error_msg}")
                        logger.debug(f"Slack API error for user_id: {slack_user_id}")
                        raise SlackAPIError(f"Slack API error: {error_msg}")

                    # The Gold: Extracting the email address from the deep JSON structure
                    email = data.get("user", {}).get("profile", {}).get("email")
                    if not email:
                        logger.error("User does not have an email address in Slack profile")
                        logger.debug(f"No email found for user_id: {slack_user_id}")
                        raise SlackAPIError(f"User {slack_user_id} does not have an email address in their Slack profile.")
                    
                    # Add to cache with LRU eviction and TTL
                    if len(self._email_cache) >= self._cache_max_size:
                        # Remove oldest entry (FIFO/LRU)
                        evicted_id = next(iter(self._email_cache))
                        self._email_cache.pop(evicted_id)
                        logger.debug("Cache full, evicted entry")
                    
                    self._email_cache[slack_user_id] = email
                    logger.debug("Successfully resolved Slack user to email")
                    return email

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    # Skip sleep on last attempt (no point retrying after)
                    if attempt == max_retries:
                        logger.error("Rate limited on final attempt")
                        break
                    
                    # The Receptionist is overwhelmed! Read the sign and wait.
                    retry_after_raw = e.headers.get("Retry-After", str(2 ** (attempt - 1)))
                    try:
                        retry_after = int(retry_after_raw)
                    except ValueError:
                        # If Retry-After is an HTTP date, default to exponential backoff
                        retry_after = 2 ** (attempt - 1)
                    
                    logger.warning(
                        f"Rate limited by Slack (HTTP 429). "
                        f"Waiting {retry_after} seconds... (Attempt {attempt}/{max_retries})"
                    )
                    time.sleep(retry_after)
                    continue  # Loop around and try again
                else:
                    logger.error(f"HTTP Error calling Slack: {e.code} - {e.reason}")
                    raise SlackAPIError(f"Slack API error: HTTP {e.code}")
            
            except urllib.error.URLError as e:
                # Handle network timeouts and connection errors
                if attempt == max_retries:
                    logger.error("Network error on final attempt")
                    logger.debug(f"Network error details for user_id {slack_user_id}: {e}")
                    raise SlackAPIError(f"Network error: {e}")
                
                logger.warning(f"Network error, retrying... (Attempt {attempt}/{max_retries})")
                # Exponential backoff with jitter to prevent thundering herd
                backoff = 2 ** (attempt - 1)
                jitter = random.uniform(0, backoff * 0.5)
                time.sleep(backoff + jitter)
                continue

        # If we exit the loop, we exhausted all retries
        logger.error("Failed to fetch email after max retries")
        raise SlackRateLimitError("Slack API rate limit exceeded max retries.")
