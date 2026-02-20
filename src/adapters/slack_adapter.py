import urllib.request
import urllib.error
import json
import time
import logging
import random
import re
from collections import OrderedDict

logger = logging.getLogger(__name__)

class SlackAPIError(Exception):
    """Base exception for Slack API errors."""
    pass

class SlackRateLimitError(SlackAPIError):
    """Raised when Slack rate limit is exceeded."""
    pass

class SlackAdapter:
    def __init__(self, bot_token: str, cache_max_size: int = 1000):
        """
        Initializes the Slack Adapter with the xoxb- Bot Token.
        
        Args:
            bot_token: Slack Bot Token (xoxb-...)
            cache_max_size: Maximum number of entries to cache (default 1000)
        """
        if not bot_token or not bot_token.startswith("xoxb-"):
            raise ValueError("A valid Slack Bot Token (xoxb-) is required.")
        
        if cache_max_size <= 0:
            raise ValueError(f"cache_max_size must be positive, got {cache_max_size}")
        
        self.bot_token = bot_token
        self.base_url = "https://slack.com/api"
        
        # LRU cache with bounded size to prevent memory leak
        self._email_cache: OrderedDict[str, str] = OrderedDict()
        self._cache_max_size = cache_max_size
    
    def __repr__(self):
        return "SlackAdapter(token=***REDACTED***)"

    def get_user_email(self, slack_user_id: str, max_retries: int = 3) -> str:
        """
        Translates a Slack user ID (e.g., U1234ABCD, W1234ABCD) into a corporate email address.
        Includes robust handling for HTTP 429 Rate Limits with caching.
        
        Note: Slack user IDs start with U (standard) or W (Enterprise Grid).
        """
        # Validate Slack user ID format: U or W followed by 8-12 alphanumeric characters
        # Slack's format: ^[UW][A-Z0-9]{8,12}$ (observed lengths: 9-11 chars total)
        if not slack_user_id or not re.match(r'^[UW][A-Z0-9]{8,12}$', slack_user_id):
            raise ValueError(f"Invalid Slack user ID format: {slack_user_id}")
        
        # Check cache first
        if slack_user_id in self._email_cache:
            logger.info(f"Cache hit for {slack_user_id}")
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
                        logger.error(f"Slack API rejected the request for {slack_user_id}: {error_msg}")
                        raise SlackAPIError(f"Slack API error: {error_msg}")

                    # The Gold: Extracting the email address from the deep JSON structure
                    email = data.get("user", {}).get("profile", {}).get("email")
                    if not email:
                        raise SlackAPIError(f"User {slack_user_id} does not have an email address in their Slack profile.")
                    
                    # Add to cache with LRU eviction
                    if len(self._email_cache) >= self._cache_max_size:
                        # Remove oldest entry (FIFO/LRU)
                        evicted_id = next(iter(self._email_cache))
                        self._email_cache.pop(evicted_id)
                        logger.debug("Cache full, evicted entry")
                    
                    self._email_cache[slack_user_id] = email
                    return email

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    # Skip sleep on last attempt (no point retrying after)
                    if attempt == max_retries:
                        logger.error(f"Rate limited on final attempt for {slack_user_id}")
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
                    logger.error(f"Network error on final attempt for {slack_user_id}: {e}")
                    raise SlackAPIError(f"Network error: {e}")
                
                logger.warning(f"Network error, retrying... (Attempt {attempt}/{max_retries})")
                # Exponential backoff with jitter to prevent thundering herd
                backoff = 2 ** (attempt - 1)
                jitter = random.uniform(0, backoff * 0.5)
                time.sleep(backoff + jitter)
                continue

        # If we exit the loop, we exhausted all retries
        logger.error(f"Failed to fetch email for {slack_user_id} after {max_retries} retries.")
        raise SlackRateLimitError("Slack API rate limit exceeded max retries.")
