# models/auth_oauth_provider.py
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class AuthOAuthProvider(models.Model):
    _name = 'auth.oauth.provider'
    _description = 'OAuth 2.0 Provider Configuration'
    _order = 'sequence, name'
    
    name = fields.Char(
        string='Provider Name',
        required=True,
        help='Display name for the OAuth provider'
    )
    
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Enable/disable this OAuth provider'
    )
    
    sequence = fields.Integer(
        string='Sequence',
        default=10,
        help='Order of display on login page'
    )
    
    flow_type = fields.Selection([
        ('authorization_code', 'Authorization Code (Recommended)'),
        ('authorization_code_pkce', 'Authorization Code with PKCE'),
        ('implicit', 'Implicit (Legacy, Not Recommended)'),
    ], string='OAuth Flow Type',
        default='authorization_code_pkce',
        required=True,
        help='OAuth 2.0 flow type to use'
    )
    
    # OAuth Endpoints
    auth_endpoint = fields.Char(
        string='Authorization Endpoint',
        required=True,
        help='OAuth authorization endpoint URL'
    )
    
    token_endpoint = fields.Char(
        string='Token Endpoint',
        required=True,
        help='OAuth token exchange endpoint URL'
    )
    
    userinfo_endpoint = fields.Char(
        string='UserInfo Endpoint',
        required=True,
        help='OAuth user information endpoint URL'
    )
    
    logout_endpoint = fields.Char(
        string='Logout Endpoint',
        help='Optional: OAuth logout endpoint for single sign-out'
    )
    
    # OAuth Credentials
    client_id = fields.Char(
        string='Client ID',
        required=True,
        help='OAuth application client ID'
    )
    
    client_secret = fields.Char(
        string='Client Secret',
        help='OAuth application client secret (required for some providers)'
    )
    
    # OAuth Configuration
    scope = fields.Char(
        string='Scope',
        default='openid profile email',
        help='OAuth scopes to request (space-separated)'
    )
    
    redirect_uri = fields.Char(
        string='Redirect URI',
        compute='_compute_redirect_uri',
        store=True,
        readonly=False,
        help='OAuth callback URI - copy this to your OAuth provider configuration'
    )
    
    # Field Mapping
    user_id_field = fields.Char(
        string='User ID Field',
        default='sub',
        help='JSON field containing unique user identifier'
    )
    
    email_field = fields.Char(
        string='Email Field',
        default='email',
        help='JSON field containing user email'
    )
    
    name_field = fields.Char(
        string='Name Field',
        default='name',
        help='JSON field containing user display name'
    )
    
    # Advanced Settings
    auth_prompt = fields.Selection([
        ('none', 'None - Silent authentication'),
        ('login', 'Login - Force re-authentication'),
        ('consent', 'Consent - Force consent screen'),
        ('select_account', 'Select Account - Account chooser'),
    ], string='Authentication Prompt',
        help='Control the authorization server login behavior'
    )
    
    auto_create_user = fields.Boolean(
        string='Auto-create Users',
        default=True,
        help='Automatically create new users on first login'
    )
    
    default_groups = fields.Many2many(
        'res.groups',
        string='Default User Groups',
        help='Groups to assign to newly created users'
    )
    
    # Provider-specific settings
    provider_type = fields.Selection([
        ('generic', 'Generic OAuth 2.0'),
        ('authentik', 'Authentik'),
        ('keycloak', 'Keycloak'),
        ('azure', 'Azure AD / Entra ID'),
        ('google', 'Google'),
        ('github', 'GitHub'),
        ('okta', 'Okta'),
    ], string='Provider Type',
        default='generic',
        help='Select for provider-specific configurations'
    )
    
    # Display
    button_text = fields.Char(
        string='Button Text',
        compute='_compute_button_text',
        store=True,
        readonly=False,
        help='Text to display on login button'
    )
    
    button_icon = fields.Char(
        string='Button Icon',
        help='Font Awesome icon class (e.g., fa-key)'
    )
    
    button_css_class = fields.Char(
        string='Button CSS Class',
        default='btn-primary',
        help='CSS class for the login button'
    )
    
    @api.depends('name')
    def _compute_button_text(self):
        for provider in self:
            if not provider.button_text:
                provider.button_text = f"Sign in with {provider.name}" if provider.name else "Sign in"
    
    @api.depends('client_id')
    def _compute_redirect_uri(self):
        for provider in self:
            if not provider.redirect_uri:
                base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                provider.redirect_uri = f"{base_url}/auth_oauth_modern/callback"
    
    @api.constrains('flow_type', 'client_secret')
    def _check_client_secret(self):
        for provider in self:
            if provider.flow_type == 'authorization_code' and not provider.client_secret:
                # Some providers require client_secret for authorization code flow
                if provider.provider_type in ['azure', 'okta']:
                    raise ValidationError(_(
                        "Client Secret is required for %s with Authorization Code flow"
                    ) % provider.name)
    
    @api.onchange('provider_type')
    def _onchange_provider_type(self):
        """Set default values based on provider type"""
        if self.provider_type == 'authentik':
            domain = self.auth_endpoint.split('/application')[0] if self.auth_endpoint else ''
            if domain:
                self.token_endpoint = f"{domain}/application/o/token/"
                self.userinfo_endpoint = f"{domain}/application/o/userinfo/"
                self.logout_endpoint = f"{domain}/application/o/logout/"
            self.scope = 'openid profile email'
            
        elif self.provider_type == 'keycloak':
            if self.auth_endpoint:
                base = self.auth_endpoint.split('/protocol')[0]
                self.token_endpoint = f"{base}/protocol/openid-connect/token"
                self.userinfo_endpoint = f"{base}/protocol/openid-connect/userinfo"
                self.logout_endpoint = f"{base}/protocol/openid-connect/logout"
            self.scope = 'openid profile email'
            
        elif self.provider_type == 'azure':
            tenant = 'common'  # or specific tenant ID
            self.auth_endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
            self.token_endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            self.userinfo_endpoint = "https://graph.microsoft.com/v1.0/me"
            self.logout_endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout"
            self.scope = 'openid profile email User.Read'
            
        elif self.provider_type == 'google':
            self.auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
            self.token_endpoint = "https://oauth2.googleapis.com/token"
            self.userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo"
            self.scope = 'openid profile email'
            
        elif self.provider_type == 'github':
            self.auth_endpoint = "https://github.com/login/oauth/authorize"
            self.token_endpoint = "https://github.com/login/oauth/access_token"
            self.userinfo_endpoint = "https://api.github.com/user"
            self.scope = 'read:user user:email'
            self.email_field = 'email'
            self.name_field = 'name'
            self.user_id_field = 'id'
    
    def test_connection(self):
        """Test the OAuth provider configuration"""
        self.ensure_one()
        
        # Import here to avoid circular dependency
        from urllib.parse import urlencode
        import requests
        
        try:
            # Test authorization endpoint
            auth_params = {
                'client_id': self.client_id,
                'response_type': 'code',
                'redirect_uri': self.redirect_uri,
                'scope': self.scope,
            }
            
            auth_url = f"{self.auth_endpoint}?{urlencode(auth_params)}"
            response = requests.head(auth_url, allow_redirects=False, timeout=10)
            
            if response.status_code not in [200, 302, 303]:
                raise ValidationError(_(
                    "Authorization endpoint returned unexpected status: %s"
                ) % response.status_code)
            
            # If we have a token endpoint, verify it exists
            if self.token_endpoint:
                response = requests.options(self.token_endpoint, timeout=10)
                if response.status_code == 405:
                    # OPTIONS might not be allowed, try GET
                    response = requests.get(self.token_endpoint, timeout=10)
                    if response.status_code not in [400, 405]:
                        raise ValidationError(_(
                            "Token endpoint seems invalid"
                        ))
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Success'),
                    'message': _('OAuth provider configuration appears valid'),
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except requests.exceptions.RequestException as e:
            raise ValidationError(_(
                "Connection test failed: %s"
            ) % str(e))
    
    def action_copy_redirect_uri(self):
        """Copy redirect URI to clipboard"""
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Redirect URI'),
                'message': self.redirect_uri,
                'type': 'info',
                'sticky': True,
            }
        }