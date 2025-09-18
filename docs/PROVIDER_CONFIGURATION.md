# Provider-Specific Configuration Guides

## Authentik Configuration

### 1. In Authentik Admin Interface

#### Create OAuth2/OpenID Provider:
1. Navigate to **Applications → Providers**
2. Click **Create** and select **OAuth2/OpenID Provider**
3. Configure:
   ```yaml
   Name: Odoo OAuth Provider
   Authentication flow: default-authentication-flow
   Authorization flow: default-provider-authorization-explicit-consent
   Protocol settings:
     Client type: Confidential
     Client ID: odoo-client-id  # Auto-generated
     Client Secret: [Copy this value]
     Redirect URIs: https://your-odoo.com/auth_oauth_modern/callback
   Advanced protocol settings:
     Access code validity: minutes=1
     Access Token validity: minutes=60
     Refresh Token validity: days=30
     Scopes: email openid profile
   ```

#### Create Application:
1. Navigate to **Applications → Applications**
2. Click **Create**
3. Configure:
   ```yaml
   Name: Odoo
   Slug: odoo
   Provider: [Select the provider created above]
   UI settings:
     Launch URL: https://your-odoo.com
   ```

### 2. In Odoo Configuration

```python
# Provider configuration in Odoo
{
    'name': 'Authentik',
    'provider_type': 'authentik',
    'flow_type': 'authorization_code_pkce',
    'client_id': 'odoo-client-id',
    'client_secret': '[Your client secret]',
    'auth_endpoint': 'https://auth.example.com/application/o/odoo/authorize/',
    'token_endpoint': 'https://auth.example.com/application/o/token/',
    'userinfo_endpoint': 'https://auth.example.com/application/o/userinfo/',
    'logout_endpoint': 'https://auth.example.com/application/o/odoo/end-session/',
    'scope': 'openid profile email',
}
```

---

## Keycloak Configuration

### 1. In Keycloak Admin Console

#### Create Client:
1. Navigate to **Clients** in your realm
2. Click **Create**
3. Basic Settings:
   ```yaml
   Client ID: odoo
   Client Protocol: openid-connect
   Root URL: https://your-odoo.com
   ```

4. Capability config:
   ```yaml
   Client authentication: On
   Authorization: Off
   Authentication flow:
     ✓ Standard flow
     ✓ Direct access grants
   ```

5. Login settings:
   ```yaml
   Valid redirect URIs: 
     - https://your-odoo.com/auth_oauth_modern/callback
     - https://your-odoo.com/*
   Valid post logout redirect URIs:
     - https://your-odoo.com/web/login
   Web origins: https://your-odoo.com
   ```

#### Get Credentials:
1. Go to **Clients → odoo → Credentials**
2. Copy the **Client Secret**

#### Configure Mappers (Optional):
1. Go to **Clients → odoo → Client scopes**
2. Click on **odoo-dedicated**
3. Add mappers for custom attributes if needed

### 2. In Odoo Configuration

```python
# Provider configuration in Odoo
{
    'name': 'Keycloak',
    'provider_type': 'keycloak',
    'flow_type': 'authorization_code_pkce',
    'client_id': 'odoo',
    'client_secret': '[Your client secret]',
    'auth_endpoint': 'https://keycloak.example.com/realms/master/protocol/openid-connect/auth',
    'token_endpoint': 'https://keycloak.example.com/realms/master/protocol/openid-connect/token',
    'userinfo_endpoint': 'https://keycloak.example.com/realms/master/protocol/openid-connect/userinfo',
    'logout_endpoint': 'https://keycloak.example.com/realms/master/protocol/openid-connect/logout',
    'scope': 'openid profile email',
}
```

---

## Azure AD / Microsoft Entra ID Configuration

### 1. In Azure Portal

#### Register Application:
1. Navigate to **Azure Active Directory → App registrations**
2. Click **New registration**
3. Configure:
   ```yaml
   Name: Odoo OAuth
   Supported account types: 
     - Single tenant (or as per your requirement)
   Redirect URI:
     Platform: Web
     URI: https://your-odoo.com/auth_oauth_modern/callback
   ```

#### Configure Authentication:
1. Go to **Authentication** section
2. Add platform configuration:
   ```yaml
   Redirect URIs: 
     - https://your-odoo.com/auth_oauth_modern/callback
   Logout URL: https://your-odoo.com/web/login
   Implicit grant and hybrid flows:
     ☐ Access tokens (not needed)
     ☐ ID tokens (not needed)
   ```

#### Create Client Secret:
1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Add description and expiry
4. **Copy the Value immediately** (shown only once)

#### API Permissions:
1. Go to **API permissions**
2. Ensure these Microsoft Graph permissions:
   - `openid` (Sign in)
   - `profile` (View basic profile)
   - `email` (View email address)
   - `User.Read` (Read user profile)

### 2. In Odoo Configuration

```python
# Provider configuration in Odoo
{
    'name': 'Microsoft',
    'provider_type': 'azure',
    'flow_type': 'authorization_code',  # Azure requires client_secret
    'client_id': '[Application (client) ID]',
    'client_secret': '[Client secret value]',
    'auth_endpoint': 'https://login.microsoftonline.com/[tenant-id]/oauth2/v2.0/authorize',
    'token_endpoint': 'https://login.microsoftonline.com/[tenant-id]/oauth2/v2.0/token',
    'userinfo_endpoint': 'https://graph.microsoft.com/v1.0/me',
    'logout_endpoint': 'https://login.microsoftonline.com/[tenant-id]/oauth2/v2.0/logout',
    'scope': 'openid profile email User.Read',
}
```

> **Note**: Replace `[tenant-id]` with your Azure AD tenant ID or use `common` for multi-tenant.

---

## Google OAuth Configuration

### 1. In Google Cloud Console

#### Create OAuth 2.0 Credentials:
1. Go to **APIs & Services → Credentials**
2. Click **Create Credentials → OAuth 2.0 Client ID**
3. Configure:
   ```yaml
   Application type: Web application
   Name: Odoo OAuth
   Authorized JavaScript origins:
     - https://your-odoo.com
   Authorized redirect URIs:
     - https://your-odoo.com/auth_oauth_modern/callback
   ```

#### Configure OAuth Consent Screen:
1. Go to **OAuth consent screen**
2. Configure:
   ```yaml
   User Type: Internal or External
   App information:
     App name: Odoo
     User support email: your-email@example.com
     App domain: your-odoo.com
   Scopes:
     - .../auth/userinfo.email
     - .../auth/userinfo.profile
     - openid
   ```

### 2. In Odoo Configuration

```python
# Provider configuration in Odoo
{
    'name': 'Google',
    'provider_type': 'google',
    'flow_type': 'authorization_code',
    'client_id': '[Your client ID].apps.googleusercontent.com',
    'client_secret': '[Your client secret]',
    'auth_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
    'token_endpoint': 'https://oauth2.googleapis.com/token',
    'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
    'scope': 'openid profile email',
}
```

---

## GitHub OAuth Configuration

### 1. In GitHub Settings

#### Create OAuth App:
1. Go to **Settings → Developer settings → OAuth Apps**
2. Click **New OAuth App**
3. Configure:
   ```yaml
   Application name: Odoo
   Homepage URL: https://your-odoo.com
   Authorization callback URL: https://your-odoo.com/auth_oauth_modern/callback
   ```

#### Get Credentials:
1. After creation, note:
   - **Client ID**
   - **Client Secret** (generate if needed)

### 2. In Odoo Configuration

```python
# Provider configuration in Odoo
{
    'name': 'GitHub',
    'provider_type': 'github',
    'flow_type': 'authorization_code',
    'client_id': '[Your client ID]',
    'client_secret': '[Your client secret]',
    'auth_endpoint': 'https://github.com/login/oauth/authorize',
    'token_endpoint': 'https://github.com/login/oauth/access_token',
    'userinfo_endpoint': 'https://api.github.com/user',
    'scope': 'read:user user:email',
    # Field mappings for GitHub
    'user_id_field': 'id',
    'email_field': 'email',
    'name_field': 'name',
}
```

---

## Okta Configuration

### 1. In Okta Admin Console

#### Create Application:
1. Navigate to **Applications → Applications**
2. Click **Create App Integration**
3. Select:
   - Sign-in method: **OIDC - OpenID Connect**
   - Application type: **Web Application**

4. Configure:
   ```yaml
   App integration name: Odoo
   Grant types:
     ✓ Authorization Code
     ✓ Refresh Token
   Sign-in redirect URIs:
     - https://your-odoo.com/auth_oauth_modern/callback
   Sign-out redirect URIs:
     - https://your-odoo.com/web/login
   Controlled access:
     - As per your organization's requirements
   ```

#### Get Credentials:
1. After creation, note from the **General** tab:
   - **Client ID**
   - **Client Secret**
   - **Okta domain**

### 2. In Odoo Configuration

```python
# Provider configuration in Odoo
{
    'name': 'Okta',
    'provider_type': 'okta',
    'flow_type': 'authorization_code_pkce',
    'client_id': '[Your client ID]',
    'client_secret': '[Your client secret]',
    'auth_endpoint': 'https://[your-okta-domain]/oauth2/default/v1/authorize',
    'token_endpoint': 'https://[your-okta-domain]/oauth2/default/v1/token',
    'userinfo_endpoint': 'https://[your-okta-domain]/oauth2/default/v1/userinfo',
    'logout_endpoint': 'https://[your-okta-domain]/oauth2/default/v1/logout',
    'scope': 'openid profile email',
}
```

---

## Testing Your Configuration

### Quick Test Checklist:

1. **Test Connection** button in Odoo works ✓
2. **Redirect URI** is correctly copied to provider ✓
3. **Login button** appears on Odoo login page ✓
4. **Authorization** redirects to provider login ✓
5. **Callback** returns to Odoo successfully ✓
6. **User creation** or linking works ✓
7. **Logout** (if configured) works properly ✓

### Use the Test Script:

```bash
python tests/test_oauth_flow.py \
  --odoo-url https://your-odoo.com \
  --auth-endpoint https://provider.com/authorize \
  --token-endpoint https://provider.com/token \
  --userinfo-endpoint https://provider.com/userinfo \
  --client-id your-client-id
```

---

## Common Configuration Mistakes

1. **Wrong redirect URI format**
   - ❌ `http://` in production (must be HTTPS)
   - ❌ Missing `/auth_oauth_modern/callback`
   - ❌ Trailing slash mismatch

2. **Incorrect scope configuration**
   - ❌ Provider doesn't support requested scopes
   - ❌ Missing required scopes (usually `openid`)

3. **Client secret issues**
   - ❌ Using public client type when secret is required
   - ❌ Expired client secret (Azure AD)
   - ❌ Wrong secret copied

4. **Endpoint URL mistakes**
   - ❌ Using discovery URL instead of actual endpoints
   - ❌ Missing realm/tenant in URL
   - ❌ Using v1 endpoints when v2 is required (or vice versa)

5. **Network/Firewall issues**
   - ❌ Odoo server can't reach OAuth provider
   - ❌ Callback URL not accessible from internet
   - ❌ SSL certificate issues