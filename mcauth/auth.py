import json
import uuid
import base64
import logging
import httpx
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from .constants import ENDPOINTS, XBOX_ERRORS, DEFAULT_HEADERS
import asyncio
import jwt
import os

logger = logging.getLogger("mcauth")

class MinecraftAuth:
    def __init__(self, client_id: str = "00000000402b5328", cache_path: Optional[str] = None, key_path: str = "ec_private.pem"):
        self.client_id = client_id
        self.cache_path = cache_path
        self.key_path = key_path
        self.http = httpx.AsyncClient(headers=DEFAULT_HEADERS)
        self._cached_tokens = self._load_cache()
        self.private_key = self._load_or_generate_key()
        self.public_key = self.private_key.public_key()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http.aclose()

    def _load_cache(self) -> Dict:
        if not self.cache_path:
            return {}
        try:
            with open(self.cache_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_cache(self):
        if not self.cache_path:
            return
        with open(self.cache_path, 'w') as f:
            json.dump(self._cached_tokens, f)

    def _load_or_generate_key(self) -> EllipticCurvePrivateKey:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self.key_path, "wb") as f:
                f.write(pem)
            return private_key

    def get_client_public_key(self) -> str:
        try:
            # Get the public key in DER format
            public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Base64 encode without padding as required by Minecraft
            encoded = base64.b64encode(public_bytes).decode('ascii').rstrip('=')
            return encoded
        except Exception as e:
            logger.error(f"Failed to generate client public key: {e}")
            raise Exception("Failed to generate client public key") from e
        
    def generate_identity_jwt(self) -> str:
        client_pub_key = self.get_client_public_key()

        payload = {
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "nbf": int(datetime.utcnow().timestamp()) - 10,
            "identityPublicKey": client_pub_key
        }

        headers = {
            "alg": "ES256",
        }

        token = jwt.encode(
            payload,
            self.private_key,
            algorithm="ES256",
            headers=headers
        )
        return token

    async def authenticate_with_microsoft(self) -> Dict[str, Any]:
        if 'microsoft' in self._cached_tokens:
            print("Using cached Microsoft token")
            return self._cached_tokens['microsoft']
        import time

        client_id = self.client_id  # Xbox Live client ID
        device_code_params = {
            'client_id': client_id,
            'scope': 'service::user.auth.xboxlive.com::MBI_SSL',
            'response_type': 'device_code'
        }

        r = await self.http.post(
            'https://login.live.com/oauth20_connect.srf',
            data=device_code_params,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        r.raise_for_status()
        device_data = r.json()

        print("\nAuthentication Instructions:")
        print(f"1. Visit: {device_data['verification_uri']}")
        print(f"2. Enter code: {device_data['user_code']}")

        token_params = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'client_id': client_id,
            'device_code': device_data['device_code']
        }

        expires = time.time() + device_data['expires_in']
        interval = device_data.get('interval', 5)

        while time.time() < expires:
            r = await self.http.post(
                'https://login.live.com/oauth20_token.srf',
                data=token_params,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            if r.status_code == 200:
                tokens = r.json()
                self._cached_tokens['microsoft'] = tokens
                self._save_cache()
                logger.debug(tokens)
                print("Successfully authenticated with Microsoft!")
                return tokens

            try:
                data = r.json()
            except Exception:
                logger.error(f"Microsoft token polling failed: non-JSON response\n{r.text}")
                raise Exception("Microsoft token polling failed with non-JSON response")

            if data.get('error') == 'authorization_pending':
                await asyncio.sleep(interval)
                continue
            elif 'error' in data:
                raise Exception(f"Auth error: {data.get('error_description', data['error'])}")

            r.raise_for_status()

        raise Exception("Authentication timed out")

    async def authenticate_with_xbox(self, for_bedrock=False) -> Dict[str, Any]:
        if self._cached_tokens.get('microsoft', {}).get('expires_in', 0) < datetime.now().timestamp():
            await self.authenticate_with_microsoft()

        ms_token = self._cached_tokens.get('microsoft', {}).get('access_token')
        if not ms_token:
            raise Exception("No Microsoft token found")

        key = 'xbox_bedrock' if for_bedrock else 'xbox'
        if key in self._cached_tokens:
            print(f"Using cached Xbox token ({key})")
            return self._cached_tokens[key]

        xbox_auth = {
            'RelyingParty': 'http://auth.xboxlive.com',
            'TokenType': 'JWT',
            'Properties': {
                'AuthMethod': 'RPS',
                'SiteName': 'user.auth.xboxlive.com',
                'RpsTicket': ms_token
            }
        }

        r = await self.http.post(ENDPOINTS['xbox']['user_auth'], json=xbox_auth)
        r.raise_for_status()
        token = r.json()

        xsts_auth = {
            'RelyingParty': ENDPOINTS['minecraft_bedrock' if for_bedrock else 'minecraft_java']['XSTS_RELYING_PARTY'],
            'TokenType': 'JWT',
            'Properties': {
                'UserTokens': [token['Token']],
                'SandboxId': 'RETAIL'
            }
        }

        r = await self.http.post(ENDPOINTS['xbox']['xsts_authorize'], json=xsts_auth)
        r.raise_for_status()
        xsts = r.json()

        self._cached_tokens[key] = xsts
        self._save_cache()
        print(f"Successfully authenticated with Xbox Live ({'Bedrock' if for_bedrock else 'Java'})")
        return xsts

    async def authenticate_minecraft_java(self) -> Dict[str, Any]:
        if 'minecraft_java' in self._cached_tokens:
            print("Using cached Minecraft Java token")
            return self._cached_tokens['minecraft_java']
        xsts = self._cached_tokens.get('xbox')
        if xsts:
            if xsts.get('NotAfter', 0) < datetime.now().timestamp():
                print("Xbox token expired, re-authenticating with Xbox")
                xsts = None
            else:
                print("Using cached Xbox token")
        else:
            print("No cached Xbox token found, authenticating with Xbox")
        if not xsts:
            xsts = await self.authenticate_with_xbox()
            print("Re-authenticated with Xbox Live")

        auth_data = {
            'identityToken': f"XBL3.0 x={xsts['DisplayClaims']['xui'][0]['uhs']};{xsts['Token']}"
        }

        r = await self.http.post(ENDPOINTS['minecraft_java']['login_with_xbox'], json=auth_data)
        r.raise_for_status()
        mc_token = r.json()

        self._cached_tokens['minecraft_java'] = mc_token
        self._save_cache()
        print("Successfully authenticated with Minecraft Java Edition!")
        return mc_token

    async def authenticate_minecraft_bedrock(self) -> Dict[str, Any]:
        # Check for valid cached token
        cached = self._cached_tokens.get('minecraft_bedrock')
        if cached:
            expires_at = cached.get('expires_at')
            if expires_at and datetime.utcnow().timestamp() < expires_at:
                print("Using cached Bedrock token")
                return cached

        # Ensure XSTS token is available
        xsts = self._cached_tokens.get('xbox_bedrock')
        if not xsts or 'DisplayClaims' not in xsts:
            print("No valid Xbox token found for Bedrock. Reauthenticating...")
            xsts = await self.authenticate_with_xbox(for_bedrock=True)

        user_hash = xsts['DisplayClaims']['xui'][0]['uhs']
        xsts_token = xsts['Token']

        identity_public_key = self.get_client_public_key()
        identity_token = f"XBL3.0 x={user_hash};{xsts_token}"

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'MCPE/UWP',
            'Authorization': identity_token
        }

        payload = {
            'identityPublicKey': identity_public_key
        }

        url = ENDPOINTS['minecraft_bedrock']['authenticate']

        try:
            response = await self.http.post(url, headers=headers, json=payload)
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            print(f"Bedrock auth failed: {e.response.status_code} - {e.response.text}")
            raise Exception("Bedrock authentication failed") from e

        result = response.json()

        # Cache the result with calculated expiration
        expires_in = result.get('expires_in', 0)
        result['expires_at'] = datetime.utcnow().timestamp() + expires_in - 10  # buffer

        self._cached_tokens['minecraft_bedrock'] = result
        self._save_cache()

        print("Successfully authenticated with Minecraft Bedrock Edition!")
        return result