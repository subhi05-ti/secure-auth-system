# Production-Ready Secure Authentication System

An enterprise-grade, highly secure, and modular **Authentication System** built using **FastAPI**, **SQLAlchemy 2.0 (Async)**, **PostgreSQL**, and **Pydantic v2**.

---

## Technical Highlights & Security Guardrails

- **Cryptographic Security**: Salted, memory-hard password hashing using **Argon2id** (`pwdlib[argon2]`).
- **Strict JWT Token Management**:
  - Short-lived **Access Tokens** (15 minutes) signed with `HS256` and unique UUID `jti`.
  - Long-lived **Refresh Tokens** with **Strict Rotation**: Every refresh token exchange revokes the used token and issues a new pair.
  - **Token Reuse Detection (RFC 6749 / BCP 195)**: If an already-revoked refresh token is presented, all active sessions for that user are immediately invalidated to neutralize token theft attacks.
  - **Immediate Access Token Revocation on Logout**: Access token `jti` is blacklisted immediately upon logout so it cannot be used even during its remaining lifespan.
  - Storage options support both `Authorization: Bearer <token>` headers and `HttpOnly`, `SameSite=Lax` cookies.
- **Dynamic Time-Limited One-Time Passwords (OTP)**:
  - Cryptographically secure 6-digit numeric OTP generation (`secrets.choice`).
  - Stored exclusively as SHA-256 hashes with short TTL (10 minutes).
  - Enforced brute-force attempt caps (max 5 failed attempts per OTP).
  - Used for **Passwordless Login**, **Email Verification**, and **Password Reset**.
- **Social Single Sign-On (SSO / OAuth2)**:
  - Multi-provider support for **Google** and **GitHub** OAuth2 flows via `httpx`/`authlib`.
  - Anti-CSRF signed state cookie validation on all OAuth handshakes.
  - Automatic account linking and verified email synchronization.
- **Role-Based & Verification Gating**:
  - FastAPI dependency injection (`get_current_user`, `get_current_verified_user`, `get_current_superuser`).
- **Resilient Defense & Rate Limiting**:
  - Sliding-window in-memory rate limiting on API requests (prevents credential stuffing & brute force).
  - Strict CORS policy restricting access to configured frontend origins.
  - Complete environment isolation via `pydantic-settings` (zero hardcoded secrets).

---

## Clean Production Folder Structure

```text
secure-auth-system/
├── alembic/                      # Database migration scripts & async env.py
│   ├── versions/                 # Migration version revisions
│   │   └── 0001_initial_auth_tables.py
│   ├── env.py
│   └── script.py.mako
├── app/
│   ├── api/                      # API Routers
│   │   └── v1/
│   │       ├── endpoints/
│   │       │   ├── auth.py       # Signup, login, refresh, logout, password reset
│   │       │   ├── oauth.py      # Google & GitHub OAuth2 endpoints with anti-CSRF
│   │       │   ├── otp.py        # Passwordless OTP login endpoints
│   │       │   └── users.py      # Profile management & protected demonstration routes
│   │       └── router.py         # Consolidated API v1 router
│   ├── auth/                     # OAuth flows & Core JWT handlers
│   │   ├── dependencies.py       # FastAPI OAuth2 security dependencies
│   │   └── jwt.py                # Token creation, signing, and verification
│   ├── core/                     # App configurations & security utilities
│   │   ├── config.py             # Strongly-typed settings via pydantic-settings
│   │   ├── rate_limit.py         # Sliding-window rate limiting middleware
│   │   ├── security.py           # Argon2id hashing, token hashing, OTP generator
│   │   └── token_blacklist.py    # Immediate access token invalidation store
│   ├── database/                 # Database engine & async session factory
│   │   ├── base.py               # DeclarativeBase class
│   │   └── session.py            # AsyncSession lifecycle provider
│   ├── models/                   # SQLAlchemy ORM Database Models
│   │   ├── oauth.py              # OAuthAccount model
│   │   ├── otp.py                # OTPCode model
│   │   ├── refresh_token.py      # RefreshToken rotation & revocation model
│   │   └── user.py               # User identity model
│   ├── schemas/                  # Pydantic Schemas (Input/Output Validation)
│   │   ├── auth.py               # Password reset & email verification schemas
│   │   ├── otp.py                # OTP request & verify schemas
│   │   ├── token.py              # Access & Refresh token schemas
│   │   └── user.py               # User registration, login, and profile schemas
│   ├── services/                 # Business Logic Layer
│   │   ├── auth_service.py       # Core authentication & token rotation orchestration
│   │   ├── email_service.py      # Asynchronous email delivery with dev fallback
│   │   ├── oauth_service.py      # Google & GitHub OAuth profile handling
│   │   └── otp_service.py        # OTP lifecycle & attempt cap enforcement
│   └── main.py                   # FastAPI application initialization & middleware
├── scripts/
│   └── test_api.py               # Automated end-to-end API test script
├── tests/                        # Comprehensive test suite (17 passed)
│   ├── conftest.py               # Async SQLite test database & HTTP client fixtures
│   ├── integration/              # Integration test flows (Auth, OTP, RBAC)
│   └── unit/                     # Unit tests (Argon2id, JWT, Rate Limiter)
├── .env.example                  # Environment configuration template
├── alembic.ini                   # Alembic configuration
├── compose.yaml                  # Multi-container Docker Compose deployment
├── Dockerfile                    # Production-ready multi-stage Python container
├── pytest.ini                    # Pytest configuration
├── requirements.txt              # Production and test dependencies
└── ruff.toml                     # Code quality and formatting configuration
```

---

## 1. Detailed Localized Setup

Follow these steps to set up and run the system locally from scratch:

### Step 1: System Prerequisites
- **Python 3.12+**
- **PostgreSQL 15+** (or Docker to run the included PostgreSQL container)
- **Git**

### Step 2: Environment Configuration
Copy the `.env.example` template to `.env`:
```bash
cp .env.example .env
```
Ensure your `.env` contains valid values for your environment:
```ini
APP_NAME=Secure Authentication System
APP_ENV=development
DEBUG=true
API_V1_PREFIX=/api/v1

# Local PostgreSQL connection string (asyncpg driver)
DATABASE_URL=postgresql+asyncpg://auth_user:change_me_local_only@localhost:5432/secure_auth

# JWT Secret key (at least 32 characters)
JWT_SECRET_KEY=your_secure_random_key_of_at_least_32_characters
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=14

# Cookie and CORS
REFRESH_COOKIE_SECURE=false
COOKIE_SAMESITE=lax
FRONTEND_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Optional SMTP Settings (if left blank, verification/OTP codes print to terminal logs)
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_EMAIL=
SMTP_STARTTLS=true

# Optional Google & GitHub OAuth credentials
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/oauth/google/callback
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:8000/api/v1/auth/oauth/github/callback
```

### Step 3: Virtual Environment Setup
Create and activate an isolated Python virtual environment:

**On Windows (PowerShell / Command Prompt):**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install all dependencies:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Run the Application Locally

The system is configured to run out-of-the-box with zero database setup (all database tables are automatically initialized on startup):
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Option B — Running with Docker Compose (Zero Setup):**
To run both the application and PostgreSQL in containers with one command:
```bash
docker compose up --build -d
```
Check container logs:
```bash
docker compose logs -f api
```
Stop services:
```bash
docker compose down
```

### Step 5: Verify the Running API
Once started, the API is available at:
- **Interactive Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Alternative ReDoc UI**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## 2. Database Migration (Alembic) Commands

The project uses **Alembic** with asynchronous SQLAlchemy support (`asyncpg`) to manage schema versions.

### Migration Commands Reference

| Operation | Command | Description |
| :--- | :--- | :--- |
| **Apply All Migrations** | `alembic upgrade head` | Migrates the database to the latest revision. |
| **Generate New Migration** | `alembic revision --autogenerate -m "add_table_xyz"` | Auto-detects model changes and generates a new migration file. |
| **Check Current Revision** | `alembic current` | Shows the active revision applied to the database. |
| **View Migration History** | `alembic history --verbose` | Lists all migrations in chronological order. |
| **Rollback Single Revision** | `alembic downgrade -1` | Rolls back the database by one revision step. |
| **Rollback to Base** | `alembic downgrade base` | Drops all managed tables and reverts to clean state. |
| **Generate SQL Offline** | `alembic upgrade head --sql` | Outputs raw SQL DDL without requiring a live database connection. |

### Running Migrations Step-by-Step
1. Ensure your `.env` contains the correct `DATABASE_URL`.
2. Run the initial migration to create all tables (`users`, `refresh_tokens`, `otp_codes`, `oauth_accounts`):
   ```bash
   alembic upgrade head
   ```
3. Verify that the migration succeeded:
   ```bash
   alembic current
   ```

---

## 3. API Testing Scripts

You have two ways to test the complete API: using the **automated Python test script** or using **individual cURL scripts**.

### Method A: Automated End-to-End Python Script
We provide a standalone testing script [scripts/test_api.py](file:///c:/Users/viyom/OneDrive/Desktop/secure-auth-system/scripts/test_api.py) that tests the entire user lifecycle in sequence:
- Health check
- User registration & duplicate check
- Login & JWT acquisition
- Accessing protected route (`/users/me`)
- Profile update
- Verification gating on premium route
- Refresh token rotation
- Token reuse detection
- Passwordless OTP request
- Secure logout & immediate access token invalidation

**To run the automated script against a running server:**
```bash
# 1. Start server in terminal 1 (if not already running)
uvicorn app.main:app --reload

# 2. Run the test script in terminal 2
python scripts/test_api.py
```

---

### Method B: Automated Unit & Integration Test Suite (`pytest`)
The project includes a complete test suite of **17 unit and integration tests** using an in-memory async SQLite engine (requires zero live database setup):
```bash
# Run all tests with verbose output
pytest -v

# Run only integration tests
pytest tests/integration/ -v

# Run only unit tests
pytest tests/unit/ -v
```

---

### Method C: Step-by-Step cURL Scripts

#### 1. Register a New User
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "full_name": "Jane Doe"
  }'
```
*Note: In local development without SMTP configured, the 6-digit verification code is printed directly to the terminal logger.*

#### 2. Verify Email Address via OTP
```bash
curl -X POST "http://localhost:8000/api/v1/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "code": "123456"
  }'
```

#### 3. User Login (Email + Password)
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```
*Response returns `access_token`, `refresh_token`, and sets an `HttpOnly`, `SameSite=Lax` cookie.*

#### 4. Access Protected Route (`/me`)
```bash
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
```

#### 5. Update Profile
```bash
curl -X PATCH "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Jane Updated"
  }'
```

#### 6. Access Premium Protected Route (Requires Verified Email)
```bash
curl -X GET "http://localhost:8000/api/v1/users/premium-demonstration" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
```

#### 7. Rotate Refresh Token
```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<YOUR_REFRESH_TOKEN>"
  }'
```
*Returns a brand new access and refresh token pair. Reusing the old refresh token triggers instant session revocation.*

#### 8. Passwordless Login via OTP
```bash
# Step 1: Request 6-digit passcode
curl -X POST "http://localhost:8000/api/v1/otp/request-login-otp" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'

# Step 2: Verify passcode and receive tokens
curl -X POST "http://localhost:8000/api/v1/otp/verify-login-otp" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "code": "123456"
  }'
```

#### 9. Password Reset via OTP
```bash
# Step 1: Request reset OTP
curl -X POST "http://localhost:8000/api/v1/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'

# Step 2: Submit OTP with new password
curl -X POST "http://localhost:8000/api/v1/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "code": "123456",
    "new_password": "NewStrongPassword456!"
  }'
```

#### 10. Secure Logout & Token Invalidation
```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<YOUR_REFRESH_TOKEN>"
  }'
```
*Instantly blacklists the access token JTI, revokes the refresh token in the database, and clears security cookies.*
