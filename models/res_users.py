# models/res_users.py
import logging
import requests
from datetime import datetime, timedelta
from odoo import models, fields, api, _
from odoo.exceptions import AccessDenied, UserError

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'
    
    # OAuth Provider Link
    oauth_provider_id = fields.Many2one(
        'auth.oauth.provider',
        string='OAuth Provider',
        help='OAuth provider used for authentication'
    )
    
    oauth_uid = fields.Char(
        string='OAuth User ID',
        help='Unique identifier from OAuth provider',
        copy=False
    )
    
    # OAuth Tokens
    oauth_access_token = fields.Char(
        string='OAuth Access Token',
        copy=False,
        groups='base.group_system'  # Only visible to system administrators
    )
    
    oauth_refresh_token = fields.Char(
        string='OAuth Refresh Token',
        copy=False,
        groups='base.group_system'
    )
    
    oauth_token_expiry = fields.Datetime(
        string='Token Expiry',
        help='Access token expiration time'
    )
    
    # OAuth User Info Cache
    oauth_user_info = fields.Text(
        string='OAuth User Info',
        help='Cached user information from OAuth provider'
    )
    
    oauth_last_sync = fields.Datetime(
        string='Last OAuth Sync',
        help='Last time user info was synchronized'
    )
    
    # OAuth Login Settings
    oauth_enabled = fields.Boolean(
        string='OAuth Login Enabled',
        default=True,
        help='Allow this user to login via OAuth'
    )
    
    force_oauth_login = fields.Boolean(
        string='Force OAuth Login',
        help='Require OAuth login for this user (disable password login)'
    )
    
    _sql_constraints = [
        ('oauth_unique', 
         'UNIQUE(oauth_provider_id, oauth_uid)',
         'OAuth UID must be unique per provider!')
    ]
    
    @api.model
    def _check_credentials(self, password, user_agent_env):
        """Override to allow OAuth token as password"""
        try:
            return super()._check_credentials(password, user_agent_env)
        except AccessDenied:
            # Check if password is actually an OAuth access token
            user = self.sudo().search([
                ('id', '=', self.env.uid),
                ('oauth_access_token', '=', password),
                ('oauth_enabled', '=', True)
            ])
            if user and user.oauth_access_token == password:
                # Check token expiry if set
                if user.oauth_token_expiry:
                    if fields.Datetime.now() > user.oauth_token_expiry:
                        # Try to refresh token
                        if user.oauth_refresh_token and user._refresh_oauth_token():
                            return
                        raise AccessDenied(_("OAuth token expired"))
                return
            raise
    
    @api.model
    def auth_oauth_modern(self, provider_id, oauth_response):
        """Authenticate user via modern OAuth flow"""
        provider = self.env['auth.oauth.provider'].sudo().browse(provider_id)
        
        if not provider.exists():
            raise AccessDenied(_("Invalid OAuth provider"))
        
        oauth_uid = oauth_response.get('sub') or oauth_response.get('id')
        email = oauth_response.get('email')
        
        if not oauth_uid:
            raise AccessDenied(_("No user ID in OAuth response"))
        
        # Find or create user
        user = self.sudo().search([
            ('oauth_provider_id', '=', provider.id),
            ('oauth_uid', '=', oauth_uid)
        ], limit=1)
        
        if not user and email:
            # Try to match by email
            user = self.sudo().search([('login', '=', email)], limit=1)
            if user:
                # Link to OAuth
                user.write({
                    'oauth_provider_id': provider.id,
                    'oauth_uid': oauth_uid,
                })
        
        if not user:
            if not provider.auto_create_user:
                raise AccessDenied(_("User creation is disabled for this OAuth provider"))
            
            if not email:
                raise AccessDenied(_("Email is required to create user"))
            
            # Get default company
            Company = self.env['res.company'].sudo()
            default_company = Company.search([], limit=1, order='sequence, id')
            
            # Create new user
            values = {
                'name': oauth_response.get('name', email.split('@')[0]),
                'login': email,
                'email': email,
                'oauth_provider_id': provider.id,
                'oauth_uid': oauth_uid,
                'oauth_enabled': True,
                'password': '',  # No password for OAuth-only users
                'company_id': default_company.id if default_company else False,
                'company_ids': [(4, default_company.id)] if default_company else False,
            }
            
            # Add default groups
            if provider.default_groups:
                values['groups_id'] = [(6, 0, provider.default_groups.ids)]
            else:
                # Set default internal user group if no groups specified
                internal_user_group = self.env.ref('base.group_user', raise_if_not_found=False)
                if internal_user_group:
                    values['groups_id'] = [(6, 0, [internal_user_group.id])]
            
            user = self.sudo().create(values)
        
        # Update OAuth info
        user.sudo().write({
            'oauth_user_info': str(oauth_response),
            'oauth_last_sync': fields.Datetime.now(),
        })
        
        return user.login
    
    def _refresh_oauth_token(self):
        """Refresh OAuth access token using refresh token"""
        self.ensure_one()
        
        if not self.oauth_refresh_token or not self.oauth_provider_id:
            return False
        
        provider = self.oauth_provider_id
        
        try:
            response = requests.post(
                provider.token_endpoint,
                data={
                    'grant_type': 'refresh_token',
                    'refresh_token': self.oauth_refresh_token,
                    'client_id': provider.client_id,
                    'client_secret': provider.client_secret or '',
                },
                timeout=30
            )
            
            if response.status_code == 200:
                tokens = response.json()
                self.sudo().write({
                    'oauth_access_token': tokens.get('access_token'),
                    'oauth_refresh_token': tokens.get('refresh_token', self.oauth_refresh_token),
                    'oauth_token_expiry': fields.Datetime.now() + timedelta(
                        seconds=tokens.get('expires_in', 3600)
                    ),
                })
                return True
                
        except Exception as e:
            _logger.error(f"Token refresh failed for user {self.login}: {str(e)}")
        
        return False
    
    def action_sync_oauth_info(self):
        """Manually sync user info from OAuth provider"""
        self.ensure_one()
        
        if not self.oauth_provider_id or not self.oauth_access_token:
            raise UserError(_("No OAuth provider or token configured"))
        
        provider = self.oauth_provider_id
        
        try:
            response = requests.get(
                provider.userinfo_endpoint,
                headers={
                    'Authorization': f'Bearer {self.oauth_access_token}'
                },
                timeout=30
            )
            
            if response.status_code == 401:
                # Try refreshing token
                if self._refresh_oauth_token():
                    # Retry with new token
                    response = requests.get(
                        provider.userinfo_endpoint,
                        headers={
                            'Authorization': f'Bearer {self.oauth_access_token}'
                        },
                        timeout=30
                    )
            
            response.raise_for_status()
            user_info = response.json()
            
            # Update user info
            update_vals = {
                'oauth_user_info': str(user_info),
                'oauth_last_sync': fields.Datetime.now(),
            }
            
            # Optionally update email/name if changed
            if user_info.get('email') and user_info['email'] != self.email:
                update_vals['email'] = user_info['email']
            
            if user_info.get('name') and user_info['name'] != self.name:
                update_vals['name'] = user_info['name']
            
            self.write(update_vals)
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Success'),
                    'message': _('User information synchronized successfully'),
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except Exception as e:
            raise UserError(_(
                "Failed to sync user information: %s"
            ) % str(e))
    
    def action_unlink_oauth(self):
        """Remove OAuth link from user account"""
        self.ensure_one()
        
        if self.force_oauth_login:
            raise UserError(_(
                "Cannot unlink OAuth from account that requires OAuth login"
            ))
        
        # Check if user has a password set
        if not self.password:
            raise UserError(_(
                "Please set a password before unlinking OAuth"
            ))
        
        self.write({
            'oauth_provider_id': False,
            'oauth_uid': False,
            'oauth_access_token': False,
            'oauth_refresh_token': False,
            'oauth_token_expiry': False,
            'oauth_user_info': False,
            'oauth_last_sync': False,
            'oauth_enabled': False,
        })
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Success'),
                'message': _('OAuth provider unlinked successfully'),
                'type': 'success',
                'sticky': False,
            }
        }
    
    @api.model
    def _cron_refresh_oauth_tokens(self):
        """Cron job to refresh expiring OAuth tokens"""
        expiring_soon = fields.Datetime.now() + timedelta(hours=1)
        
        users = self.search([
            ('oauth_token_expiry', '!=', False),
            ('oauth_token_expiry', '<', expiring_soon),
            ('oauth_refresh_token', '!=', False),
            ('oauth_enabled', '=', True)
        ])
        
        for user in users:
            try:
                user._refresh_oauth_token()
                _logger.info(f"Refreshed OAuth token for user {user.login}")
            except Exception as e:
                _logger.error(f"Failed to refresh token for user {user.login}: {str(e)}")