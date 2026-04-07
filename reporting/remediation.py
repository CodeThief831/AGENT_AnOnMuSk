"""
AGENT ANONMUSK — Remediation Database
=====================================
Context-aware remediation advice for each vulnerability type.
"""

from __future__ import annotations

from core.context import VulnType

REMEDIATION_DB: dict[VulnType, dict[str, str]] = {

    VulnType.SQLI: {
        "title": "SQL Injection Remediation",
        "summary": "Use parameterized queries to prevent SQL injection.",
        "details": """
## Immediate Actions
1. **Use parameterized/prepared statements** for ALL database queries
2. **Use ORM** (e.g., SQLAlchemy, Django ORM, Prisma) which auto-parameterize
3. **Validate input** using allowlists (not denylists)

## Code Examples

### Python (SQLAlchemy)
```python
# ❌ Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ Secure
query = text("SELECT * FROM users WHERE id = :id")
result = db.execute(query, {"id": user_id})
```

### Node.js (Knex)
```javascript
// ❌ Vulnerable
db.raw(`SELECT * FROM users WHERE id = ${userId}`)

// ✅ Secure  
db('users').where('id', userId)
```

## Additional Hardening
- Apply **least-privilege** DB permissions
- Enable **query logging** to detect anomalies
- Use **WAF rules** as defense-in-depth (not primary defense)
""",
    },

    VulnType.XSS: {
        "title": "Cross-Site Scripting (XSS) Remediation",
        "summary": "Implement context-aware output encoding.",
        "details": """
## Immediate Actions
1. **Encode all user output** based on context (HTML, JS, URL, CSS)
2. **Implement Content-Security-Policy** headers
3. **Use frameworks with auto-escaping** (React, Vue, Angular)

## CSP Header Example
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

## Additional Hardening
- Set `HttpOnly` flag on session cookies
- Use **DOMPurify** for client-side HTML sanitization
- Implement **Trusted Types** for DOM manipulation
""",
    },

    VulnType.CMDI: {
        "title": "OS Command Injection Remediation",
        "summary": "Never pass user input to shell commands.",
        "details": """
## Immediate Actions
1. **Never use shell=True** with user-controlled input
2. **Use language-native APIs** instead of shell commands
3. **Whitelist valid inputs** if shell usage is unavoidable

## Code Examples

### Python
```python
# ❌ Vulnerable
os.system(f"ping {user_input}")

# ✅ Secure
import subprocess
subprocess.run(["ping", "-c", "1", validated_host], shell=False)
```

## Additional Hardening
- Run application with **minimal OS privileges**
- Use **AppArmor/SELinux** to restrict command execution
- Implement **input validation** (alphanumeric only for hostnames)
""",
    },

    VulnType.BOLA: {
        "title": "BOLA/IDOR Remediation",
        "summary": "Implement object-level authorization checks.",
        "details": """
## Immediate Actions
1. **Verify ownership** in every API handler
2. **Use indirect references** (map user-facing IDs to internal IDs)
3. **Implement authorization middleware** that checks resource ownership

## Code Example
```python
# ❌ Vulnerable
@app.get("/api/orders/{order_id}")
def get_order(order_id: int):
    return db.query(Order).get(order_id)

# ✅ Secure
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, current_user: User):
    order = db.query(Order).get(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(403, "Forbidden")
    return order
```

## Additional Hardening
- Use **UUIDs** instead of sequential IDs
- Implement **rate limiting** per user
- Log and alert on **access pattern anomalies**
""",
    },

    VulnType.SESSION_FIXATION: {
        "title": "Session Fixation Remediation",
        "summary": "Regenerate session IDs on authentication state changes.",
        "details": """
## Immediate Actions
1. **Regenerate session ID** after login, logout, and privilege changes
2. **Set proper cookie flags**: HttpOnly, Secure, SameSite
3. **Implement session timeout** (idle and absolute)

## Code Examples
```python
# Python/Flask
@app.route('/login', methods=['POST'])
def login():
    if authenticate(username, password):
        session.regenerate()  # Critical!
        session['user'] = username
```
""",
    },

    VulnType.MISCONFIG: {
        "title": "Security Misconfiguration Remediation",
        "summary": "Review and harden server and application configuration.",
        "details": """
## Immediate Actions
1. **Set security headers**: CSP, X-Frame-Options, X-Content-Type-Options
2. **Set proper cookie flags**: HttpOnly, Secure, SameSite
3. **Disable verbose error messages** in production

## Recommended Headers
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```
""",
    },

    VulnType.RATE_LIMIT: {
        "title": "Rate Limiting Remediation",
        "summary": "Implement progressive rate limiting on sensitive endpoints.",
        "details": """
## Immediate Actions
1. **Implement rate limiting** using token bucket or sliding window
2. **Return 429 Too Many Requests** with Retry-After header
3. **Apply per-user and per-IP limits**

## Additional Hardening
- Add **CAPTCHA** after threshold
- Implement **account lockout** after failed attempts
- Use **exponential backoff** suggestions for clients
""",
    },
}


def get_remediation(vuln_type: VulnType) -> dict[str, str]:
    """Get remediation advice for a vulnerability type."""
    return REMEDIATION_DB.get(vuln_type, {
        "title": "General Security Remediation",
        "summary": "Review and fix the identified vulnerability.",
        "details": "Consult OWASP guidelines for remediation advice.",
    })
