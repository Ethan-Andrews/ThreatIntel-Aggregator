# Python + FastAPI Security Rules

Source: https://github.com/TikiTribe/claude-secure-coding-rules/blob/main/rules/languages/python/CLAUDE.md
        https://github.com/TikiTribe/claude-secure-coding-rules/blob/main/rules/backend/fastapi/CLAUDE.md

Prerequisites: `.claude/rules/owasp-2025.md`, `.claude/rules/ai-security.md`

---

## Input Validation

### Rule: Use Pydantic for All Request Validation

**Level**: `strict`

**Do**:
```python
class StackItemCreate(BaseModel):
    category: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=200)
    keywords: List[str] = Field(..., min_items=1, max_items=50)

    @validator('keywords', each_item=True)
    def validate_keyword(cls, v):
        if len(v) > 100:
            raise ValueError('Keyword too long')
        return v.strip()
```

**Don't**:
```python
@app.post("/api/stack")
async def add_item(request: Request):
    data = await request.json()  # VULNERABLE: no validation
    add_stack_item(data['category'], data['name'], data['keywords'])
```

**Refs**: OWASP A03:2025, CWE-20

---

### Rule: Validate and Sanitize Search Parameters

**Level**: `strict`

**When**: Building dynamic SQL WHERE clauses from query parameters.

**Do**:
```python
# Allowlist valid sort/order values
VALID_ORDER = {"newest", "oldest", "priority"}
order = body.order if body.order in VALID_ORDER else "newest"

# Use parameterized queries for all filter values
placeholders = ",".join("?" * len(sources))
query = f"SELECT * FROM entries WHERE source IN ({placeholders})"
conn.execute(query, sources)  # values as parameters, never interpolated
```

**Don't**:
```python
query = f"SELECT * FROM entries WHERE source = '{source}'"  # SQL Injection
query = f"ORDER BY {user_order}"  # SQL Injection via ORDER BY
```

**Refs**: CWE-89, OWASP A05:2025

---

## Authentication

### Rule: Use Timing-Safe Token Comparison

**Level**: `strict`

**Do**:
```python
import secrets

def require_auth(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    if not secrets.compare_digest(
        credentials.credentials.encode("utf-8"),
        API_SECRET_KEY.encode("utf-8"),
    ):
        raise HTTPException(status_code=401, detail="Invalid API key")
```

**Don't**:
```python
if credentials.credentials != API_SECRET_KEY:  # VULNERABLE: timing attack
    raise HTTPException(status_code=401)
```

**Why**: String comparison via `!=` leaks token length through timing differences, enabling brute-force attacks.

**Refs**: CWE-208, OWASP A07:2025

---

## CORS Configuration

### Rule: Configure CORS Restrictively

**Level**: `strict`

**Do**:
```python
import os
from fastapi.middleware.cors import CORSMiddleware

_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
origins = [o.strip() for o in _raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "PATCH", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

**Don't**:
```python
app.add_middleware(CORSMiddleware, allow_origins=["*"])  # VULNERABLE
```

**Refs**: CWE-942, OWASP A05:2025

---

## SQL Security

### Rule: Use Parameterized Queries — Never String Interpolation

**Level**: `strict`

**Do**:
```python
conn.execute("SELECT * FROM entries WHERE hash = ?", (entry_hash,))
conn.execute("UPDATE sources SET score = ? WHERE name = ?", (score, name))
conn.execute(
    "INSERT INTO stack_items (category, name, keywords) VALUES (?, ?, ?)",
    (category, name, json.dumps(keywords)),
)
```

**Don't**:
```python
conn.execute(f"SELECT * FROM entries WHERE source = '{source}'")  # SQL Injection
conn.execute("ALTER TABLE entries ADD COLUMN " + col + " " + definition)
# ^ This specific pattern is safe only because col/definition come from
# hardcoded tuples — never use user input in ALTER TABLE statements
```

**Refs**: CWE-89, OWASP A05:2025

---

## Input Handling

### Rule: Avoid Dangerous Deserialization

**Level**: `strict`

**Do**:
```python
import json
data = json.loads(user_input)       # Safe
data = yaml.safe_load(user_input)   # Safe: safe_load only
```

**Don't**:
```python
import pickle
data = pickle.loads(user_input)     # VULNERABLE: RCE
data = yaml.load(user_input, Loader=yaml.Loader)  # VULNERABLE: RCE
```

**Refs**: CWE-502, OWASP A08:2025

---

### Rule: Use Subprocess Safely

**Level**: `strict`

**Do**:
```python
import subprocess
result = subprocess.run(['ls', '-la', user_dir], capture_output=True, text=True, check=True)
```

**Don't**:
```python
import os
os.system(f'ls {user_input}')                          # Command injection
subprocess.run(f'grep {pattern} {filename}', shell=True)  # Shell injection
```

**Refs**: CWE-78, OWASP A05:2025

---

## File Operations

### Rule: Prevent Path Traversal

**Level**: `strict`

**Do**:
```python
from pathlib import Path

DATA_DIR = Path('/data').resolve()

def safe_db_path(filename: str) -> Path:
    requested = (DATA_DIR / filename).resolve()
    if not requested.is_relative_to(DATA_DIR):
        raise ValueError("Path traversal attempt")
    return requested
```

**Don't**:
```python
open(f'/data/{user_filename}')  # VULNERABLE: path traversal
```

**Refs**: CWE-22, OWASP A01:2025

---

## Error Handling

### Rule: Don't Expose Stack Traces to Clients

**Level**: `warning`

**Do**:
```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.url}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
```

**Don't**:
```python
app = FastAPI(debug=True)  # VULNERABLE in production — exposes stack traces
```

**Refs**: CWE-209, OWASP A10:2025

---

## Cryptography

### Rule: Use Secure Random Numbers

**Level**: `strict`

**Do**:
```python
import secrets
token = secrets.token_urlsafe(32)
api_key = secrets.token_hex(32)
```

**Don't**:
```python
import random
token = ''.join(random.choices('abcdef0123456789', k=32))  # VULNERABLE: predictable
```

**Refs**: CWE-330, CWE-338

---

## Quick Reference

| Rule | Level | CWE |
|------|-------|-----|
| Pydantic validation for all inputs | strict | CWE-20 |
| Timing-safe token comparison | strict | CWE-208 |
| Restrictive CORS (no wildcard) | strict | CWE-942 |
| Parameterized SQL queries | strict | CWE-89 |
| No pickle/unsafe YAML | strict | CWE-502 |
| Safe subprocess (no shell=True) | strict | CWE-78 |
| Path traversal prevention | strict | CWE-22 |
| Secure random (secrets module) | strict | CWE-330 |
| No stack traces to client | warning | CWE-209 |
