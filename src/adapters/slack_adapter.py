import urllib.request
import urllib.error
import json
import time
import logging

logger = logging.getLogger(__name__)

class SlackAPIError(Exception):
    """Base exception for Slack API errors."""
    pass

class SlackRateLimitError(SlackAPIError):
    """Raised when Slack rate limit is exceeded."""
    pass

class SlackAdapter:
    def __init__(self, bot_token: str):
        """
        Initializes the Slack Adapter with the xoxb- Bot Token.
        """
        if not bot_token or not bot_token.startswith("xoxb-"):
            raise ValueError("A valid Slack Bot Token (xoxb-) is required.")
        
        self.bot_token = bot_token
        self.base_url = "https://slack.com/api"
        self._email_cache: dict[str, str] = {}
    
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
            logger.info(f"Cache hit for {slack_user_id}")
            return self._email_cache[slack_user_id]
        
        url = f"{self.base_url}/users.info?user={slack_user_id}"
        
        # We must prove our identity to Slack using the Bearer token
        headers = {
            "Authorization": f"Bearer {self.bot_token}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        for attempt in range(1, max_retries + 1):
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
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
                    
                    # Cache the result
                    self._email_cache[slack_user_id] = email
                    return email

            except urllib.error.HTTPError as e:
                if e.code == 429:
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

        # If we exit the loop, we exhausted all retries
        logger.error(f"Failed to fetch email for {slack_user_id} after {max_retries} retries.")
        raise SlackRateLimitError("Slack API rate limit exceeded max retries.")
