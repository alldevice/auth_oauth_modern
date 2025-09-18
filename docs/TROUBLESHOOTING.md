# OAuth Modern Module - Troubleshooting Guide

## Common Error Messages and Solutions

### 1. "unsupported_response_type"

**Error Message:**
```
The authorization server does not support obtaining an authorization code using this method.
```

**Causes & Solutions:**

✅ **Provider doesn't support Authorization Code flow**
- Check provider documentation
- Some legacy providers only support implicit flow
- Solution: Enable implicit flow support in provider settings

✅ **Wrong flow configuration**
```python
# In Odoo provider settings, ensure:
flow_type = 'authorization_code_pkce'  # or 'authorization_code'
```

✅ **PKCE not supported by provider**
```python
# Switch from PKCE to regular authorization code:
flow_type = 'authorization_code'
```

---

### 2. "invalid_client"

**Error Message:**
```
Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)
```

**Causes & Solutions:**

✅ **Wrong Client ID or Secret**
- Double-check the client_id in both Odoo and provider
- Regenerate client secret if needed
- Ensure no extra spaces or characters

✅ **Client type mismatch**
- Provider expects "Confidential" client but secret not provided
- Solution: Add client_secret in Odoo configuration

✅ **Authentication method mismatch**
```python
# Some providers require specific auth methods
# Try adding to token request headers:
headers = {
    'Authorization': f'Basic {base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()}'
}
```

---

### 3. "redirect_uri_mismatch"

**Error Message:**
```
The redirect URI provided is missing or does not match
```

**Causes & Solutions:**

✅ **Exact match required**
```bash
# These are DIFFERENT:
https://odoo.example.com/auth_oauth_modern/callback
https://odoo.example.com/auth_oauth_modern/callback/
http://odoo.example.com/auth_oauth_modern/callback  # HTTP vs HTTPS
```

✅ **Multiple Odoo instances**
- Each instance needs its own redirect URI
- Add all URIs to provider configuration

✅ **Behind proxy/load balancer**
```nginx
# Nginx configuration - preserve scheme
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header Host $http_host;
```

```python
# Odoo configuration
proxy_mode = True
```

---

### 4. "invalid_grant"

**Error Message:**
```
The provided authorization grant is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client.
```

**Causes & Solutions:**

✅ **Authorization code already used**
- Codes are single-use only
- User clicked back button and retried
- Solution: Start the flow again

✅ **Code expired**
- Most codes expire in 1-10 minutes
- Network delay or slow server
- Solution: Complete flow faster or extend code lifetime in provider

✅ **PKCE verification failed**
```python
# Ensure session persistence across requests
# Check session configuration in Odoo
session_db = postgresql://...
```

---

### 5. "access_denied"

**Error Message:**
```
The resource owner or authorization server denied the request
```

**Causes & Solutions:**

✅ **User cancelled authentication**
- User clicked "Cancel" on provider login
- Solution: User education or SSO enforcement

✅ **Insufficient permissions**
- User doesn't have access to the OAuth application
- Solution: Grant access in provider settings

✅ **Consent required**
```python
# In provider configuration:
auth_prompt = 'consent'  # Forces consent screen
# or
auth_prompt = 'none'  # Silent auth if possible
```

---

## Connection and Network Issues

### SSL/TLS Certificate Errors

**Symptoms:**
```python
SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```

**Solutions:**

✅ **Self-signed certificates** (Development only!)
```python
# In controllers/main.py - ADD FOR TESTING ONLY
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
```

✅ **Missing CA certificates**
```bash
# Ubuntu/Debian
apt-get install ca-certificates
update-ca-certificates

# CentOS/RHEL
yum install ca-certificates
update-ca-trust
```

✅ **Behind corporate proxy**
```python
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1
```

### Timeout Errors

**Symptoms:**
```
TimeoutError: The read operation timed out
```

**Solutions:**

✅ **Increase timeout values**
```python
# In controllers/main.py
response = requests.post(
    provider.token_endpoint,
    data=token_data,
    headers=headers,
    timeout=60  # Increase from 30
)
```

✅ **Check firewall rules**
```bash
# Test connectivity
curl -v https://oauth-provider.com/token
telnet oauth-provider.com 443
```

---

## User Authentication Issues

### User Not Created

**Symptoms:**
- Login succeeds but user doesn't exist in Odoo

**Solutions:**

✅ **Auto-create disabled**
```python
# Check provider settings
auto_create_user = True  # Must be enabled
```

✅ **Email missing from provider response**
```python
# Add email to scope
scope = 'openid profile email'

# Or map different field
email_field = 'mail'  # or 'upn' for Azure
```

### Wrong User Linked

**Symptoms:**
- OAuth login links to wrong Odoo user

**Solutions:**

✅ **Email collision**
- Multiple users with same email
- Solution: Use unique OAuth UID instead

✅ **Clear OAuth links**
```sql
-- SQL to clear OAuth links (use carefully!)
UPDATE res_users 
SET oauth_provider_id = NULL,
    oauth_uid = NULL,
    oauth_access_token = NULL
WHERE id = [user_id];
```

---

## Debugging Techniques

### 1. Enable Debug Logging

```python
# In Odoo config file
[options]
log_level = debug
log_handler = odoo.addons.auth_oauth_modern:DEBUG
```

### 2. Check Browser Network Tab

1. Open Browser Developer Tools (F12)
2. Go to Network tab
3. Preserve log across redirects
4. Look for:
   - OAuth authorize request
   - Callback with code/error
   - Token exchange (won't be visible)

### 3. Manual Token Request

Test token endpoint manually:
```bash
curl -X POST https://provider.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=https://odoo.com/auth_oauth_modern/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_SECRET" \
  -d "code_verifier=YOUR_PKCE_VERIFIER"
```

### 4. Database Inspection

```sql
-- Check OAuth providers
SELECT * FROM auth_oauth_provider;

-- Check user OAuth settings
SELECT 
    login,
    oauth_provider_id,
    oauth_uid,
    oauth_enabled,
    force_oauth_login,
    oauth_last_sync
FROM res_users 
WHERE oauth_provider_id IS NOT NULL;

-- Check recent login attempts
SELECT * FROM res_users_log 
ORDER BY create_date DESC 
LIMIT 10;
```

### 5. Session Debugging

```python
# Add to controller for debugging
_logger.info(f"Session ID: {request.session.sid}")
_logger.info(f"Session data: {request.session.items()}")
_logger.info(f"OAuth state: {request.session.get('oauth_state')}")
```

---

## Performance Issues

### Slow Authentication

**Causes & Solutions:**

✅ **Token endpoint slow**
- Add caching for provider metadata
- Use connection pooling

✅ **UserInfo endpoint slow**
```python
# Cache user info for session
request.session['oauth_user_info_cache'] = user_info
request.session['oauth_user_info_timestamp'] = time.time()
```

✅ **Database locks**
```sql
-- Check for locks
SELECT * FROM pg_locks WHERE NOT granted;
```

---

## Provider-Specific Issues

### Authentik

**Issue:** "detail: No provider found for application"

**Solution:**
- Ensure application is linked to provider
- Check provider's authorization flow is set

### Keycloak

**Issue:** "error_description: Client secret not provided in request"

**Solution:**
```python
# Keycloak requires client_secret even for PKCE
client_secret = 'your-secret'  # Required
flow_type = 'authorization_code'  # Not PKCE
```

### Azure AD

**Issue:** "AADSTS50011: The reply URL specified in the request does not match"

**Solution:**
- Azure is very strict about redirect URIs
- Must include all variations (with/without www)
- Check tenant settings for multi-tenant apps

### Google

**Issue:** "Error 400: invalid_request"

**Solution:**
- Google requires exact scope names
- Use 'email' not 'mail'
- Enable Google+ API in console

---

## Emergency Recovery

### Reset All OAuth Configuration

```sql
-- Backup first!
BEGIN;

-- Clear all OAuth providers
DELETE FROM auth_oauth_provider;

-- Clear all user OAuth links
UPDATE res_users 
SET oauth_provider_id = NULL,
    oauth_uid = NULL,
    oauth_access_token = NULL,
    oauth_refresh_token = NULL,
    oauth_enabled = FALSE,
    force_oauth_login = FALSE;

-- COMMIT or ROLLBACK based on results
COMMIT;
```

### Bypass OAuth for Admin

```python
# Temporary admin bypass - ADD TO CONTROLLER
if kw.get('admin_bypass') == 'secret_key' and kw.get('login') == 'admin':
    # Allow password login for admin
    return super().web_login(redirect=redirect, **kw)
```

### Create Fallback Admin

```bash
# Create new admin via shell
./odoo-bin shell -d your_database

# In shell:
admin = env['res.users'].create({
    'name': 'Emergency Admin',
    'login': 'emergency_admin',
    'password': 'TempPass123!',
    'groups_id': [(6, 0, [env.ref('base.group_system').id])],
})
env.cr.commit()
```

---

## Getting Help

### Information to Collect

When requesting help, provide:

1. **Odoo version**: 17.0
2. **Module version**: Check __manifest__.py
3. **Provider type**: Authentik/Keycloak/Azure/etc.
4. **Error messages**: Complete error with stack trace
5. **Network setup**: Proxy/Load balancer/Direct
6. **Logs**: Odoo and provider logs
7. **Test results**: From test_oauth_flow.py

### Log Collection Script

```bash
#!/bin/bash
# Collect debug information

echo "=== OAuth Debug Info ===" > oauth_debug.txt
echo "Date: $(date)" >> oauth_debug.txt
echo "" >> oauth_debug.txt

echo "=== Provider Configuration ===" >> oauth_debug.txt
psql -d your_database -c "SELECT * FROM auth_oauth_provider;" >> oauth_debug.txt

echo "=== Recent Logs ===" >> oauth_debug.txt
tail -n 100 /var/log/odoo/odoo.log | grep -E "oauth|OAuth" >> oauth_debug.txt

echo "=== Network Test ===" >> oauth_debug.txt
curl -I https://your-oauth-provider.com >> oauth_debug.txt 2>&1

echo "Debug info saved to oauth_debug.txt"
```