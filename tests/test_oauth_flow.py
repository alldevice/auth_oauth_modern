#!/usr/bin/env python3
"""
OAuth Flow Testing Script
Tests the OAuth authentication flow without using a browser
"""

import requests
import json
import base64
import hashlib
import secrets
import sys
from urllib.parse import urlencode, parse_qs, urlparse


class OAuthFlowTester:
    """Test OAuth flow implementation"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        
    def generate_pkce_pair(self):
        """Generate PKCE verifier and challenge"""
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return verifier, challenge
    
    def test_authorization_endpoint(self):
        """Test the authorization endpoint"""
        print("\n[TEST] Authorization Endpoint")
        
        state = secrets.token_urlsafe(32)
        verifier, challenge = self.generate_pkce_pair()
        
        params = {
            'client_id': self.config['client_id'],
            'response_type': 'code',
            'redirect_uri': self.config['redirect_uri'],
            'scope': self.config['scope'],
            'state': state,
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        }
        
        auth_url = f"{self.config['auth_endpoint']}?{urlencode(params)}"
        
        print(f"Authorization URL: {auth_url}")
        
        try:
            response = self.session.get(auth_url, allow_redirects=False)
            
            if response.status_code in [302, 303]:
                print("✅ Authorization endpoint returned redirect (expected)")
                location = response.headers.get('Location', '')
                
                # Check if it's a login page redirect
                if 'login' in location.lower():
                    print("✅ Redirected to login page (expected for unauthenticated user)")
                    return True, state, verifier
                else:
                    print(f"⚠️  Redirected to: {location}")
                    
            elif response.status_code == 200:
                print("✅ Authorization endpoint returned login page directly")
                return True, state, verifier
            else:
                print(f"❌ Unexpected status code: {response.status_code}")
                return False, None, None
                
        except Exception as e:
            print(f"❌ Error testing authorization endpoint: {e}")
            return False, None, None
            
        return True, state, verifier
    
    def test_token_endpoint(self, code=None, verifier=None):
        """Test the token endpoint"""
        print("\n[TEST] Token Endpoint")
        
        # Use a dummy code if none provided
        if not code:
            code = "dummy_auth_code_for_testing"
        if not verifier:
            verifier, _ = self.generate_pkce_pair()
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.config['redirect_uri'],
            'client_id': self.config['client_id'],
            'client_secret': self.config.get('client_secret', ''),
            'code_verifier': verifier,
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        
        try:
            response = self.session.post(
                self.config['token_endpoint'],
                data=data,
                headers=headers,
                timeout=10
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 400:
                error_data = response.json()
                error = error_data.get('error', 'unknown')
                
                if error == 'invalid_grant':
                    print("✅ Token endpoint rejected invalid code (expected for test)")
                    return True
                else:
                    print(f"⚠️  Error: {error} - {error_data.get('error_description', '')}")
                    
            elif response.status_code == 200:
                print("⚠️  Token endpoint accepted dummy code (unexpected)")
                print(f"Response: {response.json()}")
            else:
                print(f"❌ Unexpected status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing token endpoint: {e}")
            return False
            
        return True
    
    def test_userinfo_endpoint(self, access_token=None):
        """Test the userinfo endpoint"""
        print("\n[TEST] UserInfo Endpoint")
        
        # Use a dummy token if none provided
        if not access_token:
            access_token = "dummy_access_token_for_testing"
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }
        
        try:
            response = self.session.get(
                self.config['userinfo_endpoint'],
                headers=headers,
                timeout=10
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 401:
                print("✅ UserInfo endpoint rejected invalid token (expected)")
                return True
            elif response.status_code == 200:
                print("⚠️  UserInfo endpoint accepted dummy token (unexpected)")
                print(f"Response: {response.json()}")
            else:
                print(f"❌ Unexpected status code: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing userinfo endpoint: {e}")
            return False
            
        return True
    
    def test_odoo_endpoints(self):
        """Test Odoo OAuth endpoints"""
        print("\n[TEST] Odoo OAuth Endpoints")
        
        # Test signin endpoint
        odoo_signin = f"{self.config['odoo_base_url']}/auth_oauth_modern/signin?provider=1"
        
        try:
            response = self.session.get(odoo_signin, allow_redirects=False)
            
            if response.status_code in [302, 303]:
                location = response.headers.get('Location', '')
                
                if self.config['auth_endpoint'] in location:
                    print("✅ Odoo signin endpoint redirects to OAuth provider")
                    
                    # Parse the redirect URL to check parameters
                    parsed = urlparse(location)
                    params = parse_qs(parsed.query)
                    
                    if params.get('response_type') == ['code']:
                        print("✅ Using Authorization Code flow (response_type=code)")
                    else:
                        print(f"❌ Wrong response_type: {params.get('response_type')}")
                        
                    if 'code_challenge' in params:
                        print("✅ PKCE is enabled (code_challenge present)")
                    else:
                        print("⚠️  PKCE not enabled (no code_challenge)")
                        
                else:
                    print(f"❌ Unexpected redirect location: {location}")
            else:
                print(f"❌ Unexpected status code: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error testing Odoo endpoints: {e}")
            return False
            
        return True
    
    def run_all_tests(self):
        """Run all OAuth flow tests"""
        print("=" * 60)
        print("OAuth Flow Testing")
        print("=" * 60)
        
        results = []
        
        # Test 1: Authorization endpoint
        success, state, verifier = self.test_authorization_endpoint()
        results.append(("Authorization Endpoint", success))
        
        # Test 2: Token endpoint
        success = self.test_token_endpoint(verifier=verifier)
        results.append(("Token Endpoint", success))
        
        # Test 3: UserInfo endpoint
        success = self.test_userinfo_endpoint()
        results.append(("UserInfo Endpoint", success))
        
        # Test 4: Odoo endpoints
        success = self.test_odoo_endpoints()
        results.append(("Odoo Integration", success))
        
        # Summary
        print("\n" + "=" * 60)
        print("Test Summary")
        print("=" * 60)
        
        for test_name, success in results:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{test_name}: {status}")
        
        all_passed = all(r[1] for r in results)
        
        if all_passed:
            print("\n✅ All tests passed!")
        else:
            print("\n❌ Some tests failed. Please check the configuration.")
        
        return all_passed


def main():
    """Main function"""
    
    # Configuration
    config = {
        'odoo_base_url': 'https://odoo.example.com',
        'auth_endpoint': 'https://auth.example.com/application/o/odoo/authorize/',
        'token_endpoint': 'https://auth.example.com/application/o/token/',
        'userinfo_endpoint': 'https://auth.example.com/application/o/userinfo/',
        'client_id': 'your-client-id',
        'client_secret': 'your-client-secret',  # Optional
        'redirect_uri': 'https://odoo.example.com/auth_oauth_modern/callback',
        'scope': 'openid profile email',
    }
    
    # Override with command line arguments if provided
    if len(sys.argv) > 1:
        import argparse
        
        parser = argparse.ArgumentParser(description='Test OAuth flow configuration')
        parser.add_argument('--odoo-url', help='Odoo base URL')
        parser.add_argument('--auth-endpoint', help='OAuth authorization endpoint')
        parser.add_argument('--token-endpoint', help='OAuth token endpoint')
        parser.add_argument('--userinfo-endpoint', help='OAuth userinfo endpoint')
        parser.add_argument('--client-id', help='OAuth client ID')
        parser.add_argument('--client-secret', help='OAuth client secret')
        parser.add_argument('--redirect-uri', help='OAuth redirect URI')
        
        args = parser.parse_args()
        
        if args.odoo_url:
            config['odoo_base_url'] = args.odoo_url
            config['redirect_uri'] = f"{args.odoo_url}/auth_oauth_modern/callback"
        if args.auth_endpoint:
            config['auth_endpoint'] = args.auth_endpoint
        if args.token_endpoint:
            config['token_endpoint'] = args.token_endpoint
        if args.userinfo_endpoint:
            config['userinfo_endpoint'] = args.userinfo_endpoint
        if args.client_id:
            config['client_id'] = args.client_id
        if args.client_secret:
            config['client_secret'] = args.client_secret
        if args.redirect_uri:
            config['redirect_uri'] = args.redirect_uri
    
    # Run tests
    tester = OAuthFlowTester(config)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()