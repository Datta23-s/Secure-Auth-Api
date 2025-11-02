# Secure-Auth-Api
The application implements a complete enterprise-level authentication system.JWT Creation & Validation​
The system features short-lived access tokens (15-minute expiry) with long-lived refresh tokens (7-day expiry) using the HS256 algorithm. This follows best practices that keep tokens small and focused on identity, storing only essential claims like user_id, org_id, and role. The implementation includes proper token verification on every request, with tokens transmitted exclusively over secure HTTPS connections.​

OAuth 2.0 & OpenID Connect​
The system architecture supports OAuth 2.0 authorization flows with proper token exchange mechanisms. OpenID Connect functionality is demonstrated through ID tokens paired with access tokens, enabling user authentication and single sign-on capabilities.​

Role-Based Access Control (RBAC)​
The application implements granular role-based permissions across three user tiers:

Admin: Full system access including user management, report generation, and 2FA administration

Manager: Operations oversight with reporting and user viewing capabilities

User: Personal profile access and basic operations

Each role has explicit permission mappings to API endpoints, with middleware validating role claims before granting access.​

Multi-Factor Authentication (TOTP & Email OTP)​​
The system provides:

TOTP (Time-based One-Time Password): QR code generation for authenticator apps with 30-second code rotation

Email OTP: 6-digit verification codes sent to user email with 5-minute expiry and maximum 3 verification attempts

Account lockout protection: Temporary lockout after 5 failed login attempts​

Security Implementation Details
Password Security: Passwords are hashed using bcrypt-style algorithms with salting (10 salt rounds recommended) to defend against brute-force attacks. The system validates passwords against complexity requirements: minimum 8 characters, requiring uppercase, lowercase, numbers, and special characters.​

Token Lifecycle Management: The implementation follows the recommended pattern:​

Access tokens expire quickly (15 minutes) to limit breach exposure

Refresh tokens remain valid longer (7 days) while enabling transparent token renewal

Refresh token rotation detects and prevents reuse attacks by invalidating token families when reuse is detected​

CORS & Security Headers: The API configures:​

Explicit allowed origins (no wildcard in production)

Restricted HTTP methods per endpoint

Custom headers validation

Secure flag cookies with HttpOnly attribute

Standard security headers including HSTS, X-Frame-Options, and X-Content-Type-Options

Error Handling: Implements RFC 9457 Problem Details format with:​

Descriptive but non-leaking error messages

Consistent HTTP status codes (400 for client errors, 401/403 for auth failures, 500 for server errors)

Request correlation IDs for debugging

No sensitive data exposure in error responses

Database Schema Design​
The system uses a normalized identity management structure:

Users table: Contains user_id (primary key), username, email, hashed_password, role_id, created_at

Credentials table: Stores password_hash, salt, last_login, failed_attempts

Roles table: Defines role names and associated permissions

Permissions table: Maps permissions to roles using a many-to-many relationship

Audit Log: Tracks authentication events, API access, and security-relevant actions

RESTful API Design​
Following resource-based architecture with proper HTTP methods:

GET for retrieving resources

POST for creating new entities

PUT/PATCH for updates

DELETE for resource removal

Logical nesting showing resource relationships (e.g., /api/users/{id}/permissions)

Rate Limiting & DDoS Protection​
The system implements:

5 login attempts per 15 minutes per user

100 API requests per minute per authenticated user

IP-based request throttling

Progressive backoff after repeated failures

Stable user ID-based rate limiting instead of IP rotation workarounds

Demo Credentials
Pre-configured test accounts with different roles:

Admin: admin@company.com / AdminPass123!

Manager: manager@company.com / ManagerPass123!

User: user@company.com / UserPass123!
