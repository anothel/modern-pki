# Webhook Receiver Examples

Modern PKI webhook receivers must verify the raw request body before parsing JSON.
Run `python scripts/test_webhook_receiver_verification.py` to check the shared
HMAC and replay-window rules.

Expected headers:

- `X-Modern-PKI-Event`: event type.
- `X-Modern-PKI-Timestamp`: RFC3339 UTC timestamp.
- `X-Modern-PKI-Signature`: `sha256=` plus lowercase hex HMAC-SHA256 over `timestamp + "." + raw_body`.

Reject requests when the timestamp is more than 5 minutes away from receiver time.

## Go

```go
func verifyModernPKIWebhook(secret string, timestamp string, signature string, body []byte, now time.Time) bool {
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	if d := now.UTC().Sub(ts.UTC()); d > 5*time.Minute || d < -5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(signature))
}
```

## Node.js

```js
import crypto from "node:crypto";

export function verifyModernPKIWebhook(secret, timestamp, signature, body) {
  const ts = Date.parse(timestamp);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Date.now() - ts) > 300000) return false;

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(timestamp);
  hmac.update(".");
  hmac.update(body);
  const expected = "sha256=" + hmac.digest("hex");
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signature);
  return expectedBuffer.length === actualBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}
```

## Python

```python
import hashlib
import hmac
from datetime import datetime, timezone

def verify_modern_pki_webhook(
    secret: str,
    timestamp: str,
    signature: str,
    body: bytes,
    now: datetime,
) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.tzinfo is None:
        return False
    if abs((now.astimezone(timezone.utc) - ts.astimezone(timezone.utc)).total_seconds()) > 300:
        return False
    msg = timestamp.encode("utf-8") + b"." + body
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```
