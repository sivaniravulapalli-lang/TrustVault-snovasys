Threat Model — TrustVault

This document tracks identified attack vectors, mitigations, and test verifications as the system evolves.

#	Threat	Mitigation	Proven by	Status
1	Credential Guessing / Brute-Force	Rate limiting derived from audit logs (5 failed attempts per IP/account window), Argon2 password hashing.	tests/test_auth.py	Closed
2	User Enumeration via Login Timing	Login verification executes a dummy Argon2 hash check even when the user is not found, keeping response time constant.	tests/test_auth.py	Closed
3	Token Forgery / Weak Secrets	Application enforces at least 32-character high-entropy SECRET_KEY on startup, rejecting default/weak keys.	tests/test_auth.py	Closed
4	Self-Assigned Admin/Owner Privilege at Registration	Registration endpoint binds role strictly to viewer; role escalation is only possible by an admin.	tests/test_auth.py	Closed
5	Tampered or Expired JWT Tokens	JWT expiration pinned to 60 minutes with strict cryptographic signature verification on every protected route.	tests/test_auth.py	Closed
Known Trade-offs Accepted for Day 1
Stateless Tokens: JWTs cannot be blacklisted prior to the 60-minute expiry without maintaining a centralized redis/cache layer. We compensate by verifying user status and permissions directly in the database on every document request.