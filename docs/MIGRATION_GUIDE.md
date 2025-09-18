# Migration Guide: auth_oauth → auth_oauth_modern

## Overview

This guide helps you migrate from Odoo's legacy `auth_oauth` module (using implicit flow) to the new `auth_oauth_modern` module (using authorization code flow with PKCE).

## Migration Strategies

### Strategy 1: Parallel Deployment (Recommended)
- Keep both modules running simultaneously
- Migrate users gradually
- Test thoroughly before full switch

### Strategy 2: Big Bang Migration
- Replace auth_oauth completely
- All users switch at once
- Requires downtime and coordination

### Strategy 3: Phased by User Groups
- Migrate specific departments/teams first
- Learn from early adopters
- Roll out to all users after validation

---

## Pre-Migration Checklist

### 1. System Requirements
- [ ] Odoo 17.0 or compatible version
- [ ] Python packages: `requests`, `hashlib`, `secrets`
- [ ] HTTPS enabled (required for production)
- [ ] Database backup completed

### 2. Provider Compatibility
- [ ] OAuth provider supports Authorization Code flow
- [ ] Client credentials available (ID and Secret)
- [ ] Redirect URIs can be updated
- [ ] Test environment available

### 3. User Impact Assessment
```sql
-- Count affected users
SELECT COUNT(*) as oauth_users 
FROM res_users 
WHERE oauth_provider_id IS NOT NULL;

-- List OAuth providers in use
SELECT DISTINCT 
    aop.name,
    COUNT(ru.id) as user_count
FROM res_users ru
JOIN auth_oauth_provider aop ON ru.oauth_provider_id = aop.id
GROUP BY aop.name;
```

---

## Step-by-Step Migration

### Phase 1: Preparation

#### 1.1 Backup Everything
```bash
# Database backup
pg_dump your_database > backup_$(date +%Y%m%d).sql

# Configuration backup
cp -r /etc/odoo /etc/odoo.backup.$(date +%Y%m%d)
```

#### 1.2 Export Existing OAuth Configuration
```sql
-- Export current OAuth providers
\COPY (SELECT * FROM auth_oauth_provider) 
TO '/tmp/oauth_providers_backup.csv' 
WITH CSV HEADER;

-- Export user OAuth mappings
\COPY (
    SELECT 
        ru.id,
        ru.login,
        ru.oauth_uid,
        aop.name as provider_name,
        aop.client_id
    FROM res_users ru
    LEFT JOIN auth_oauth_provider aop ON ru.oauth_provider_id = aop.id
    WHERE ru.oauth_provider_id IS NOT NULL
) TO '/tmp/oauth_users_backup.csv' 
WITH CSV HEADER;
```

### Phase 2: Installation

#### 2.1 Install auth_oauth_modern
```bash
# Copy module to addons directory
cp -r auth_oauth_modern /opt/odoo/addons/

# Set permissions
chown -R odoo:odoo /opt/odoo/addons/auth_oauth_modern
chmod -R 755 /opt/odoo/addons/auth_oauth_modern

# Update module list
sudo -u odoo /opt/odoo/odoo-bin \
    -d your_database \
    -u base \
    --stop-after-init
```

#### 2.2 Install via UI
1. Go to Apps menu
2. Update Apps List
3. Search for "OAuth Modern Authentication"
4. Click Install

### Phase 3: Configuration Migration

#### 3.1 Provider Migration Script
```python
#!/usr/bin/env python3
"""
Migrate OAuth providers from auth_oauth to auth_oauth_modern
"""

import psycopg2
import json

# Database connection
conn = psycopg2.connect(
    host="localhost",
    database="your_database",
    user="odoo",
    password="your_password"
)
cur = conn.cursor()

# Get old providers
cur.execute("""
    SELECT 
        name,
        client_id,
        enabled,
        auth_endpoint,
        scope,
        validation_endpoint
    FROM auth_oauth_provider
    WHERE enabled = true
""")

old_providers = cur.fetchall()

# Migration mapping
PROVIDER_MAPPING = {
    'Authentik': {
        'provider_type': 'authentik',
        'flow_type': 'authorization_code_pkce',
        'token_endpoint_suffix': '/application/o/token/',
        'userinfo_endpoint_suffix': '/application/o/userinfo/',
    },
    'Google': {
        'provider_type': 'google',
        'flow_type': 'authorization_code',
        'token_endpoint': 'https://oauth2.googleapis.com/token',
        'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
    },
    # Add more mappings as needed
}

# Create new providers
for provider in old_providers:
    name = provider[0]
    client_id = provider[1]
    auth_endpoint = provider[3]
    scope = provider[4] or 'openid profile email'
    
    # Determine provider type and endpoints
    mapping = PROVIDER_MAPPING.get(name, {
        'provider_type': 'generic',
        'flow_type': 'authorization_code_pkce',
    })
    
    # Insert new provider
    cur.execute("""
        INSERT INTO auth_oauth_provider (
            name,
            active,
            provider_type,
            flow_type,
            client_id,
            auth_endpoint,
            token_endpoint,
            userinfo_endpoint,
            scope,
            auto_create_user,
            created_uid,
            create_date,
            write_uid,
            write_date
        ) VALUES (
            %s || ' (Modern)',
            true,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            true,
            1,
            NOW(),
            1,
            NOW()
        ) RETURNING id
    """, (
        name,
        mapping.get('provider_type'),
        mapping.get('flow_type'),
        client_id,
        auth_endpoint,
        mapping.get('token_endpoint', ''),
        mapping.get('userinfo_endpoint', ''),
        scope
    ))
    
    new_provider_id = cur.fetchone()[0]
    print(f"Created provider: {name} (Modern) with ID {new_provider_id}")

conn.commit()
cur.close()
conn.close()
```

#### 3.2 Update Provider Endpoints
1. Go to **Settings → Users & Companies → OAuth Providers**
2. For each provider:
   - Click on the provider
   - Update Token Endpoint
   - Update UserInfo Endpoint
   - Add Client Secret if required
   - Test Connection

### Phase 4: User Migration

#### 4.1 Parallel Mode Setup
```python
# Allow both modules to coexist
# In auth_oauth_modern/models/res_users.py, add:

class ResUsers(models.Model):
    _inherit = 'res.users'
    
    # Rename fields to avoid conflicts
    oauth_modern_provider_id = fields.Many2one(
        'auth.oauth.provider',
        string='OAuth Provider (Modern)',
    )
    
    oauth_modern_uid = fields.Char(
        string='OAuth User ID (Modern)',
    )
    
    # Check both old and new OAuth
    def _check_credentials(self, password, user_agent_env):
        try:
            # Try modern OAuth first
            if self.oauth_modern_provider_id:
                # Modern OAuth logic
                pass
        except:
            # Fall back to legacy OAuth
            pass
        
        return super()._check_credentials(password, user_agent_env)
```

#### 4.2 User Communication Template
```markdown
Subject: Important: OAuth Login System Update

Dear [User],

We are upgrading our login system to enhance security. 

**What's changing:**
- More secure authentication method
- Same login experience for you
- Better integration with [Provider Name]

**Action required:**
- Next time you log in, use the new "Sign in with [Provider] (Modern)" button
- Your existing credentials remain the same
- First login might take a few seconds longer

**Timeline:**
- New system available: [Date]
- Old system deprecated: [Date + 30 days]
- Old system removed: [Date + 60 days]

For assistance, contact: support@company.com

Thank you for your cooperation.
```

### Phase 5: Testing

#### 5.1 Test User Creation
```python
# Create test users for each migration scenario

# Scenario 1: New user via OAuth
test_new_user = {
    'email': 'test_new@example.com',
    'provider': 'Authentik (Modern)'
}

# Scenario 2: Existing user linking
test_existing = {
    'email': 'existing@example.com',
    'current_provider': 'Authentik',
    'new_provider': 'Authentik (Modern)'
}

# Scenario 3: User with multiple providers
test_multi = {
    'email': 'multi@example.com',
    'providers': ['Google', 'Authentik (Modern)']
}
```

#### 5.2 Migration Validation Script
```python
#!/usr/bin/env python3
"""
Validate OAuth migration
"""

def validate_migration():
    checks = []
    
    # Check 1: All providers migrated
    old_providers = env['auth.oauth.provider'].search([
        ('name', 'not like', '(Modern)')
    ])
    new_providers = env['auth.oauth.provider'].search([
        ('name', 'like', '(Modern)')
    ])
    
    checks.append({
        'test': 'Provider Migration',
        'passed': len(new_providers) >= len(old_providers),
        'details': f"Old: {len(old_providers)}, New: {len(new_providers)}"
    })
    
    # Check 2: User mappings preserved
    users_with_old = env['res.users'].search_count([
        ('oauth_provider_id', '!=', False)
    ])
    users_with_new = env['res.users'].search_count([
        ('oauth_modern_provider_id', '!=', False)
    ])
    
    checks.append({
        'test': 'User Mappings',
        'passed': users_with_new > 0,
        'details': f"Old: {users_with_old}, New: {users_with_new}"
    })
    
    # Check 3: Endpoints configured
    for provider in new_providers:
        has_endpoints = all([
            provider.auth_endpoint,
            provider.token_endpoint,
            provider.userinfo_endpoint
        ])
        checks.append({
            'test': f'Endpoints for {provider.name}',
            'passed': has_endpoints,
            'details': 'All endpoints configured' if has_endpoints else 'Missing endpoints'
        })
    
    return checks

# Run validation
results = validate_migration()
for check in results:
    status = "✅" if check['passed'] else "❌"
    print(f"{status} {check['test']}: {check['details']}")
```

### Phase 6: Cutover

#### 6.1 Gradual Cutover
```python
# Week 1-2: Enable new providers, keep old ones
# Week 3-4: Hide old providers, monitor issues
# Week 5-6: Disable old providers
# Week 7-8: Remove old module

# Hide old providers
env['auth.oauth.provider'].search([
    ('name', 'not like', '(Modern)')
]).write({'active': False})
```

#### 6.2 Emergency Rollback Plan
```sql
-- Restore old providers
UPDATE auth_oauth_provider 
SET active = true 
WHERE name NOT LIKE '%(Modern)%';

-- Disable new providers
UPDATE auth_oauth_provider 
SET active = false 
WHERE name LIKE '%(Modern)%';

-- Restore user mappings
UPDATE res_users 
SET oauth_provider_id = oauth_provider_id_backup
WHERE oauth_provider_id_backup IS NOT NULL;
```

---

## Post-Migration

### Cleanup Tasks

#### 1. Remove Old Module
```bash
# After successful migration
pip uninstall auth_oauth  # If it was pip installed

# Remove from addons
rm -rf /opt/odoo/addons/auth_oauth

# Update Odoo
sudo -u odoo /opt/odoo/odoo-bin \
    -d your_database \
    -u base \
    --stop-after-init
```

#### 2. Database Cleanup
```sql
-- Remove backup columns
ALTER TABLE res_users 
DROP COLUMN IF EXISTS oauth_provider_id_backup;

-- Clean up old sessions
DELETE FROM ir_session 
WHERE create_date < NOW() - INTERVAL '30 days';
```

#### 3. Update Documentation
- Update login procedures
- Update security policies
- Update user training materials
- Update IT support runbooks

---

## Troubleshooting Migration Issues

### Issue: Users Can't Login After Migration

**Solution:**
```python
# Temporary dual-auth support
# Add to res_users.py

@api.model
def authenticate(self, db, login, password, user_agent_env):
    try:
        # Try new OAuth
        uid = self._login_oauth_modern(db, login, password)
        if uid:
            return uid
    except:
        pass
    
    try:
        # Try old OAuth
        uid = self._login_oauth_legacy(db, login, password)
        if uid:
            return uid
    except:
        pass
    
    # Try regular password
    return super().authenticate(db, login, password, user_agent_env)
```

### Issue: Provider Endpoints Not Found

**Solution:**
```python
# Auto-detect endpoints based on provider type
def detect_endpoints(self):
    if self.provider_type == 'authentik':
        base = self.auth_endpoint.split('/application')[0]
        self.token_endpoint = f"{base}/application/o/token/"
        self.userinfo_endpoint = f"{base}/application/o/userinfo/"
```

### Issue: Session State Lost

**Solution:**
```python
# Ensure session persistence
# In odoo.conf:
[options]
db_name = your_database
dbfilter = ^your_database$
list_db = False
session_dir = /var/lib/odoo/sessions
```

---

## Success Metrics

Track these metrics to measure migration success:

1. **Login Success Rate**
   - Before: X%
   - After: Should be ≥ X%

2. **Authentication Time**
   - Before: Y seconds
   - After: Should be ≤ Y+2 seconds

3. **Support Tickets**
   - Week 1: Expected spike
   - Week 2-4: Should decrease
   - Week 5+: Below baseline

4. **User Adoption**
   ```sql
   -- Track adoption rate
   SELECT 
       DATE(oauth_last_sync) as date,
       COUNT(*) as logins
   FROM res_users
   WHERE oauth_modern_provider_id IS NOT NULL
   GROUP BY DATE(oauth_last_sync)
   ORDER BY date DESC;
   ```

---

## Support Resources

- **Documentation**: `/docs/` folder in module
- **Test Script**: `tests/test_oauth_flow.py`
- **Community**: Odoo forums, GitHub issues
- **Emergency Contact**: Define your IT support contact

## Final Checklist

- [ ] All users migrated
- [ ] Old module disabled/removed
- [ ] Documentation updated
- [ ] Support team trained
- [ ] Monitoring in place
- [ ] Backup retention policy confirmed
- [ ] Success metrics achieved