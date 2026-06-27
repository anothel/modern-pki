# Webhook Receiver Examples

Modern PKI webhook receivers must verify the raw request body before parsing JSON.

Expected headers:

- `X-Modern-PKI-Event`: event type.
- `X-Modern-PKI-Timestamp`: Unix seconds.
- `X-Modern-PKI-Signature`: `sha256=` plus lowercase hex HMAC-SHA256 over `timestamp + "." + raw_body`.

Reject requests when the timestamp is more than 5 minutes away from receiver time.

## Go

```go
func verifyModernPKIWebhook(secret string, timestamp string, signature string, body []byte, now time.Time) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > 5*time.Minute || d < -5*time.Minute {
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
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Date.now() / 1000 - ts) > 300) return false;

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
import time

def verify_modern_pki_webhook(secret: str, timestamp: str, signature: str, body: bytes) -> bool:
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > 300:
        return False
    msg = timestamp.encode("utf-8") + b"." + body
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```
