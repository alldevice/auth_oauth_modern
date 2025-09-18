# controllers/main.py
import json
import logging
import secrets
import hashlib
import base64
from urllib.parse import urlencode, parse_qs, urlparse
import werkzeug.utils
import requests
from odoo import http, _
from odoo.http import request
from odoo.exceptions import AccessDenied, UserError
from odoo.addons.web.controllers.utils import ensure_db

_logger = logging.getLogger(__name__)


class OAuthModernController(http.Controller):
    """Handles OAuth 2.0 Authorization Code Flow with PKCE"""
    
    def _generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        # Generate a random 43-128 character code verifier
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate code challenge using SHA256
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    @http.route('/auth_oauth_modern/signin', type='http', auth='none', csrf=False)
    def signin(self, **kw):
        """Initiate OAuth login - redirect to authorization server"""
        ensure_db()
        
        provider_id = kw.get('provider')
        if not provider_id:
            return "Missing provider parameter"
        
        provider = request.env['auth.oauth.provider'].sudo().browse(int(provider_id))
        if not provider.exists():
            return "Invalid provider"
        
        # Generate PKCE pair
        code_verifier, code_challenge = self._generate_pkce_pair()
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store state and PKCE verifier in session
        request.session['oauth_state'] = state
        request.session['oauth_code_verifier'] = code_verifier
        request.session['oauth_provider_id'] = provider.id
        
        # Build authorization URL
        params = {
            'client_id': provider.client_id,
            'response_type': 'code',  # Authorization Code Flow
            'redirect_uri': provider.redirect_uri or request.httprequest.url_root + 'auth_oauth_modern/callback',
            'scope': provider.scope or 'openid profile email',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        
        # Add optional parameters
        if provider.auth_prompt:
            params['prompt'] = provider.auth_prompt
        
        auth_url = f"{provider.auth_endpoint}?{urlencode(params)}"
        
        _logger.info(f"Redirecting to OAuth provider: {provider.name}")
        return werkzeug.utils.redirect(auth_url)
    
    @http.route('/auth_oauth_modern/callback', type='http', auth='none', csrf=False)
    def callback(self, **kw):
        """Handle OAuth callback with authorization code"""
        ensure_db()
        
        # Verify state to prevent CSRF
        state = kw.get('state')
        if not state or state != request.session.get('oauth_state'):
            _logger.error("OAuth state mismatch - possible CSRF attempt")
            return werkzeug.utils.redirect('/web/login?oauth_error=invalid_state')
        
        # Check for errors from authorization server
        if 'error' in kw:
            error = kw.get('error')
            error_description = kw.get('error_description', '')
            _logger.error(f"OAuth error: {error} - {error_description}")
            return werkzeug.utils.redirect(f'/web/login?oauth_error={error}')
        
        # Get authorization code
        code = kw.get('code')
        if not code:
            _logger.error("No authorization code received")
            return werkzeug.utils.redirect('/web/login?oauth_error=no_code')
        
        # Retrieve stored values
        provider_id = request.session.get('oauth_provider_id')
        code_verifier = request.session.get('oauth_code_verifier')
        
        if not provider_id or not code_verifier:
            _logger.error("Missing session data")
            return werkzeug.utils.redirect('/web/login?oauth_error=session_expired')
        
        provider = request.env['auth.oauth.provider'].sudo().browse(provider_id)
        
        try:
            # Exchange authorization code for tokens
            tokens = self._exchange_code_for_tokens(provider, code, code_verifier)
            
            # Get user info using access token
            user_info = self._get_user_info(provider, tokens['access_token'])
            
            # Authenticate or create user
            login = self._authenticate_user(provider, user_info, tokens)
            
            # Clean up session
            request.session.pop('oauth_state', None)
            request.session.pop('oauth_code_verifier', None)
            request.session.pop('oauth_provider_id', None)
            
            # Login user
            request.session.authenticate(request.db, login, tokens['access_token'])
            
            # Redirect to home or next URL
            redirect_url = request.params.get('redirect') or '/web'
            return werkzeug.utils.redirect(redirect_url)
            
        except Exception as e:
            _logger.error(f"OAuth authentication failed: {str(e)}", exc_info=True)
            return werkzeug.utils.redirect(f'/web/login?oauth_error=authentication_failed&message={str(e)}')
    
    def _exchange_code_for_tokens(self, provider, code, code_verifier):
        """Exchange authorization code for access and refresh tokens"""
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': provider.redirect_uri or request.httprequest.url_root + 'auth_oauth_modern/callback',
            'client_id': provider.client_id,
            'code_verifier': code_verifier,  # PKCE verifier
        }
        
        # Add client secret if configured (some providers require it)
        if provider.client_secret:
            token_data['client_secret'] = provider.client_secret
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        
        try:
            response = requests.post(
                provider.token_endpoint,
                data=token_data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            tokens = response.json()
            
            if 'access_token' not in tokens:
                raise UserError(_("No access token received from OAuth provider"))
            
            return tokens
            
        except requests.exceptions.RequestException as e:
            _logger.error(f"Token exchange failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                _logger.error(f"Response: {e.response.text}")
            raise UserError(_("Failed to exchange authorization code for tokens"))
    
    def _get_user_info(self, provider, access_token):
        """Retrieve user information from OAuth provider"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }
        
        try:
            response = requests.get(
                provider.userinfo_endpoint,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            # Normalize user info based on provider type
            normalized_info = self._normalize_user_info(provider, user_info)
            
            return normalized_info
            
        except requests.exceptions.RequestException as e:
            _logger.error(f"Failed to get user info: {str(e)}")
            raise UserError(_("Failed to retrieve user information from OAuth provider"))
    
    def _normalize_user_info(self, provider, user_info):
        """Normalize user info based on provider type and mapping"""
        normalized = {}
        
        # Standard OIDC claims
        normalized['sub'] = user_info.get('sub') or user_info.get('id') or user_info.get('uid')
        normalized['email'] = user_info.get('email') or user_info.get('mail')
        normalized['name'] = user_info.get('name') or user_info.get('display_name') or \
                            f"{user_info.get('given_name', '')} {user_info.get('family_name', '')}".strip()
        normalized['given_name'] = user_info.get('given_name') or user_info.get('first_name')
        normalized['family_name'] = user_info.get('family_name') or user_info.get('last_name')
        normalized['preferred_username'] = user_info.get('preferred_username') or user_info.get('username')
        
        # Handle provider-specific mappings if configured
        if provider.user_id_field:
            normalized['sub'] = user_info.get(provider.user_id_field, normalized['sub'])
        if provider.email_field:
            normalized['email'] = user_info.get(provider.email_field, normalized['email'])
        if provider.name_field:
            normalized['name'] = user_info.get(provider.name_field, normalized['name'])
        
        # Store raw user info for reference
        normalized['raw_info'] = user_info
        
        return normalized
    
    def _authenticate_user(self, provider, user_info, tokens):
        """Authenticate or create user based on OAuth info"""
        Users = request.env['res.users'].sudo()
        
        oauth_uid = user_info.get('sub')
        email = user_info.get('email')
        
        if not oauth_uid:
            raise UserError(_("No user ID received from OAuth provider"))
        
        # Try to find existing user by OAuth UID
        user = Users.search([
            ('oauth_uid', '=', oauth_uid),
            ('oauth_provider_id', '=', provider.id)
        ], limit=1)
        
        if not user and email:
            # Try to find by email
            user = Users.search([('login', '=', email)], limit=1)
            
            if user:
                # Link existing user to OAuth provider
                user.write({
                    'oauth_provider_id': provider.id,
                    'oauth_uid': oauth_uid,
                    'oauth_access_token': tokens.get('access_token'),
                    'oauth_refresh_token': tokens.get('refresh_token'),
                })
        
        if not user:
            # Create new user
            if not email:
                raise UserError(_("Email address is required to create a new user"))
            
            user_vals = {
                'name': user_info.get('name') or email.split('@')[0],
                'login': email,
                'email': email,
                'oauth_provider_id': provider.id,
                'oauth_uid': oauth_uid,
                'oauth_access_token': tokens.get('access_token'),
                'oauth_refresh_token': tokens.get('refresh_token'),
                'active': True,
            }
            
            # Set default groups if configured
            if provider.default_groups:
                user_vals['groups_id'] = [(6, 0, provider.default_groups.ids)]
            
            user = Users.create(user_vals)
        else:
            # Update tokens
            user.write({
                'oauth_access_token': tokens.get('access_token'),
                'oauth_refresh_token': tokens.get('refresh_token'),
            })
        
        return user.login
    
    @http.route('/auth_oauth_modern/logout', type='http', auth='user')
    def logout(self, redirect='/web/login'):
        """Logout user and optionally trigger OAuth logout"""
        user = request.env.user
        
        # Check if user has OAuth provider with logout endpoint
        if user.oauth_provider_id and user.oauth_provider_id.logout_endpoint:
            provider = user.oauth_provider_id
            
            # Build logout URL with redirect
            logout_params = {
                'post_logout_redirect_uri': request.httprequest.url_root + redirect,
            }
            
            if user.oauth_access_token:
                logout_params['id_token_hint'] = user.oauth_access_token
            
            logout_url = f"{provider.logout_endpoint}?{urlencode(logout_params)}"
            
            # Clear Odoo session
            request.session.logout(keep_db=True)
            
            # Redirect to OAuth logout
            return werkzeug.utils.redirect(logout_url)
        
        # Standard Odoo logout
        request.session.logout(keep_db=True)
        return werkzeug.utils.redirect(redirect)