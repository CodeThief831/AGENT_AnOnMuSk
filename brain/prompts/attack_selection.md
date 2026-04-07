Based on the reconnaissance data below, create a prioritized attack plan.

{{RECON_DATA}}

## Instructions

Analyze the recon results and identify the most promising attack vectors.
Consider:

1. **BOLA/IDOR (Highest Priority)**: Look for object ID patterns (user_id, account_id, org_id) in endpoints
2. **XSS**: Parameters that reflect user input (search, query, name, redirect)
3. **SQLi**: Parameters that might query databases (id, sort, filter, order)
4. **Auth Issues**: Login/register/reset endpoints — test for username enumeration
5. **Session Flaws**: Cookie flags, token rotation, fixation
6. **Command Injection**: Parameters that might interact with OS (file, path, cmd)
7. **API Abuse**: Rate limits on sensitive endpoints, unauthorized enumeration
8. **Nuclei Scan**: Always recommend as baseline coverage

## Response Format

Respond with a JSON object:
```json
{
    "attack_plan": [
        {
            "module": "module_name",
            "priority": 1,
            "params": {
                "target_urls": ["https://..."],
                "parameters": ["param1", "param2"],
                "notes": "Testing rationale"
            },
            "reasoning": "Detailed reasoning for this attack vector"
        }
    ]
}
```

Available modules:
- `username_enum` — Test login/reset for verbose error messages
- `session_audit` — Check cookie flags and session management
- `session_fixation` — Test session persistence across state changes
- `bola_idor` — Test object-level authorization
- `xss` — Cross-site scripting detection
- `sqli` — SQL injection detection
- `command_injection` — OS command injection
- `rate_limit` — API rate limit testing
- `api_bola` — API-level BOLA/authorization testing
- `nuclei` — Template-based vulnerability scanning
