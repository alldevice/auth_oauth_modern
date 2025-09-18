# Root __init__.py
from . import models
from . import controllers

# models/__init__.py
from . import auth_oauth_provider
from . import res_users
from . import ir_config_parameter

# controllers/__init__.py
from . import main

# models/ir_config_parameter.py
# Optional: Extend IR Config Parameter for OAuth settings
from odoo import models, fields, api

class IrConfigParameter(models.Model):
    _inherit = 'ir.config_parameter'
    
    @api.model
    def get_oauth_modern_params(self):
        """Get all OAuth Modern configuration parameters"""
        return {
            'oauth_modern.default_flow': self.sudo().get_param('oauth_modern.default_flow', 'authorization_code_pkce'),
            'oauth_modern.force_https': self.sudo().get_param('oauth_modern.force_https', 'True') == 'True',
            'oauth_modern.token_refresh_interval': int(self.sudo().get_param('oauth_modern.token_refresh_interval', '3600')),
            'oauth_modern.debug_mode': self.sudo().get_param('oauth_modern.debug_mode', 'False') == 'True',
        }