# ACME client compatibility

Only verified or deliberately blocked client states belong here.

| Client | OS / shell | Account key | Challenge | Smoke result | Evidence |
| --- | --- | --- | --- | --- | --- |
| lego v4.35.2+dev-release | Windows non-admin PowerShell | P-256 | HTTP-01 webroot | Pass | `scripts/acme-smoke/run-certbot-smoke.ps1 -Client lego -LegoPath .tmp\lego-bin\lego.exe -WorkDir .tmp\acme-smoke-fresh -StartService -Run -DirectoryTimeoutSec 60`; output included `Server responded with a certificate.` |
| certbot 5.6.0 | Windows non-admin PowerShell | not reached | HTTP-01 webroot / standalone | Blocked before ACME traffic | certbot exits with `certbot must be run on a shell with administrative rights`; rerun from Linux or elevated Windows. |

Protocol fixture coverage:

- `TestACMEProtocolCertbotCompatibilityFixture` covers directory, nonce,
  account, order, POST-as-GET, HTTP-01 challenge, finalize, and certificate
  chain behavior that the smoke clients exercise.
- RSA, P-256, and Ed25519 account-key protocol tests cover local key-type
  compatibility independent of live client support.
