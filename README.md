# OAuth Modern Authentication Module for Odoo

## Overview
This module implements OAuth 2.0 Authorization Code Flow with PKCE support for Odoo 17, replacing the legacy implicit flow used by the standard `auth_oauth` module.

## Features
✅ **Authorization Code Flow** - Modern, secure OAuth 2.0 flow  
✅ **PKCE Support** - Additional security with Proof Key for Code Exchange  
✅ **Multiple Provider Support** - Authentik, Keycloak, Azure AD, Google, GitHub  
✅ **Token Refresh** - Automatic token renewal using refresh tokens  
✅ **User Auto-Creation** - Optional automatic user provisioning  
✅ **Single Sign-Out** - Support for provider logout endpoints  

## Installation

1. **Download the Module**
   ```bash
   cd /path/to/odoo/addons
   git clone <repository> auth_oauth_modern
   ```

2. **Install Dependencies**
   ```bash
   pip install requests
   ```

3. **Update Odoo Module List**
   - Go to Apps menu in Odoo
   - Click "Update Apps List"
   - Search for "OAuth Modern Authentication"
   - Click Install

## Configuration

### Step 1: Configure Your Identity Provider

#### For Authentik:
1. Create a new OAuth2/OpenID Provider
2. Set these parameters:
   ```
   Client type: Confidential
   Redirect URIs: https://your-odoo.com/auth_oauth_modern/callback
   Grant types: authorization_code
   Signing Key: Select your certificate
   ```
3. Create an Application and link it to the provider
4. Note down:
   - Client ID
   - Client Secret
   - Authorization endpoint
   - Token endpoint
   - UserInfo endpoint

#### For Keycloak:
1. Create a new Client in your realm
2. Settings:
   ```
   Client Protocol: openid-connect
   Access Type: confidential
   Valid Redirect URIs: https://your-odoo.com/auth_oauth_modern/callback
   ```
3. Note the credentials and endpoints

### Step 2: Configure in Odoo

1. Go to **Settings → Users & Companies → OAuth Providers**
2. Click **Create** and fill in:

   **Basic Configuration:**
   - Name: `Authentik` (or your provider)
   - Provider Type: Select your provider
   - Flow Type: `Authorization Code with PKCE`
   - Active: ✅

   **OAuth Credentials:**
   - Client ID: `<your-client-id>`
   - Client Secret: `<your-client-secret>` (if required)
   
   **Endpoints:**
   - Authorization: `https://auth.example.com/application/o/odoo/authorize/`
   - Token: `https://auth.example.com/application/o/token/`
   - UserInfo: `https://auth.example.com/application/o/userinfo/`
   - Logout: `https://auth.example.com/application/o/odoo/end-session/` (optional)

3. Click **Test Connection** to verify
4. Save the configuration

### Step 3: Configure Redirect URI in Provider

1. In Odoo OAuth Provider form, click **Copy Redirect URI**
2. Add this URI to your OAuth provider's allowed redirect URIs

## Usage

### For End Users:
1. Go to Odoo login page
2. Click "Sign in with [Provider Name]"
3. Authenticate with your identity provider
4. You'll be redirected back to Odoo and logged in

### For Administrators:

#### Link Existing Users:
Users with matching email addresses will be automatically linked on first OAuth login.

#### Force OAuth Login:
1. Go to user form
2. Check "Force OAuth Login"
3. User must use OAuth (password login disabled)

#### Manual User Sync:
1. Go to user form
2. Click "Sync OAuth Info"
3. Updates user data from provider

## Troubleshooting

### Common Issues:

**"unsupported_response_type" Error**
- Ensure provider supports Authorization Code flow
- Check flow_type is set correctly in Odoo

**"invalid_client" Error**
- Verify Client ID and Client Secret
- Check credentials in both Odoo and provider

**"redirect_uri_mismatch" Error**
- Copy exact redirect URI from Odoo
- Ensure HTTPS is used in production
- Check for trailing slashes

**Token Expired Issues**
- Enable refresh tokens in provider
- Check cron job for token refresh is active

### Debug Mode:
Enable debug logging:
```python
# In Odoo configuration file
log_level = debug
log_handler = odoo.addons.auth_oauth_modern:DEBUG
```

## Security Considerations

1. **Always use HTTPS** in production
2. **Keep client secrets secure** - use Odoo's password fields
3. **Set appropriate scopes** - request only needed permissions
4. **Regular token refresh** - configure the cron job
5. **Session management** - implement appropriate timeouts

## API Reference

### Provider Model Fields:
```python
provider.flow_type          # 'authorization_code_pkce'
provider.auth_endpoint      # Authorization URL
provider.token_endpoint     # Token exchange URL  
provider.userinfo_endpoint  # User information URL
provider.client_id          # OAuth client ID
provider.client_secret      # OAuth client secret
```

### User OAuth Fields:
```python
user.oauth_provider_id      # Linked provider
user.oauth_uid              # Provider user ID
user.oauth_access_token     # Current access token
user.oauth_refresh_token    # Refresh token
user.oauth_enabled          # OAuth login enabled
```

## Customization

### Custom Provider Mappings:
Override `_normalize_user_info` in the controller:
```python
def _normalize_user_info(self, provider, user_info):
    normalized = super()._normalize_user_info(provider, user_info)
    
    # Custom mapping for your provider
    if provider.provider_type == 'custom':
        normalized['email'] = user_info.get('emailAddress')
        normalized['name'] = f"{user_info.get('firstName')} {user_info.get('lastName')}"
    
    return normalized
```

### Additional User Attributes:
Extend the user creation in `_authenticate_user`:
```python
def _authenticate_user(self, provider, user_info, tokens):
    # ... existing code ...
    
    # Add custom fields
    user_vals['department'] = user_info.get('department')
    user_vals['employee_id'] = user_info.get('employeeNumber')
    
    # ... continue with user creation
```

## Migration from auth_oauth

### Coexistence:
This module can work alongside the standard `auth_oauth` module:
- Existing OAuth configurations continue working
- New providers use the modern flow
- Users can have both types linked

### Migration Steps:
1. Install `auth_oauth_modern`
2. Create new provider configurations
3. Test with subset of users
4. Gradually migrate all users
5. Disable old OAuth providers

## Support

### Resources:
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect](https://openid.net/connect/)

### Provider-Specific Docs:
- [Authentik](https://docs.goauthentik.io/)
- [Keycloak](https://www.keycloak.org/documentation)
- [Azure AD](https://docs.microsoft.com/azure/active-directory/)

## License
LGPL-3.0

## Contributing
Pull requests welcome! Please ensure:
- Code follows Odoo conventions
- Tests included for new features
- Documentation updated
- Security best practices followed