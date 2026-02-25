# Demo 01 - Basic Info.plist scan

## What this shows

`Info.plist` in this folder is a deliberately insecure iOS app property list.
IPASNITCH scans it statically (no device, no network) and flags:

1. **ATS globally disabled** - `NSAllowsArbitraryLoads = true` (high).
2. **Per-domain insecure HTTP** - `legacy.example.com` allows cleartext HTTP
   loads, with the exception widened to all subdomains (high).
3. **Weak TLS** - the same domain pins a minimum TLS version of `TLSv1.0` (medium).
4. **Cleartext endpoint** - an `http://` API base URL string (medium).
5. **Embedded secrets** - an AWS access key id and a credential-like key whose
   value is high-entropy (critical / high).

## How to run

```sh
# Human-readable table
python -m ipasnitch scan demos/01-basic/Info.plist

# JSON for CI piping
python -m ipasnitch scan demos/01-basic/Info.plist --format json | jq '.results[0].counts'

# Gate a build: fail only on high-or-worse
python -m ipasnitch scan demos/01-basic/Info.plist --fail-on high
```

## Expected result

- Multiple findings reported, including at least one `critical` (the AWS key)
  and several `high` (ATS disabled, insecure HTTP domain).
- Exit code is **1** because findings exceed the default `--fail-on low`
  threshold (this is the CI gate signaling failure).
