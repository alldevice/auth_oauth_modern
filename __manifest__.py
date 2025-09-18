# __manifest__.py
{
    'name': 'OAuth Modern Authentication',
    'version': '17.0.1.0.0',
    'category': 'Authentication',
    'summary': 'OAuth 2.0 Authorization Code Flow with PKCE support',
    'description': """
        Modern OAuth Authentication Module
        ===================================
        
        This module implements OAuth 2.0 Authorization Code Flow with PKCE
        (Proof Key for Code Exchange) for enhanced security.
        
        Features:
        - Authorization Code Flow support
        - PKCE implementation for additional security
        - Compatible with modern identity providers (Authentik, Keycloak, etc.)
        - Backward compatible with existing OAuth module
    """,
    'author': 'Your Company',
    'website': 'https://yourcompany.com',
    'depends': [
        'base',
        'web',
        'base_setup',
        'auth_signup',  # Optional, for signup functionality
    ],
    'data': [
        'security/ir.model.access.csv',
        'data/auth_oauth_data.xml',
        'views/auth_oauth_provider_views.xml',
        'views/res_users_views.xml',
        'views/login_template.xml',
    ],
    'external_dependencies': {
        'python': ['requests', 'secrets', 'hashlib', 'base64'],
    },
    'installable': True,
    'application': False,
    'auto_install': False,
    'license': 'LGPL-3',
}