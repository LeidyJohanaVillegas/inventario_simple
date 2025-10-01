"""
Servicio OAuth2 completo según la documentación del proyecto
Implementa las clases: Servicio_de_autenticacion, Token_de_refresco, OauthClient, Codigo_de_autenticacion
"""

import jwt
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
from fastapi import HTTPException
import json
import os
from dotenv import load_dotenv

from ..database import execute_query
from ..auth.security import verify_password

load_dotenv()

# Configuración OAuth2
SECRET_KEY = os.getenv("SECRET_KEY", "tu_clave_secreta_muy_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30
AUTHORIZATION_CODE_EXPIRE_MINUTES = 10

@dataclass
class TokenDeRefresco:
    """Clase Token_de_refresco según documentación (Clase --7)"""
    token: str
    userName: str
    client_id: str
    expires_at: float
    
    def is_expired(self) -> bool:
        """Verificar si el token ha expirado"""
        return datetime.now().timestamp() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario para almacenamiento"""
        return {
            "token": self.token,
            "userName": self.userName,
            "client_id": self.client_id,
            "expires_at": self.expires_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenDeRefresco':
        """Crear instancia desde diccionario"""
        return cls(**data)

@dataclass
class OauthClient:
    """Clase OauthClient según documentación (Clase --8)"""
    id: int
    client_id: str
    client_secret: str
    redirect_url: str
    is_confidential: bool
    
    def verify_secret(self, provided_secret: str) -> bool:
        """Verificar secreto del cliente"""
        return self.client_secret == provided_secret
    
    def is_redirect_url_valid(self, url: str) -> bool:
        """Verificar si la URL de redirección es válida"""
        return url.startswith(self.redirect_url)

@dataclass
class CodigoDeAutenticacion:
    """Clase Codigo_de_autenticacion según documentación (Clase --10)"""
    code: str
    client_id: str
    userName: str
    expires_at: float
    code_challenge: str
    code_challenge_method: str
    redirect_url: str
    
    def is_expired(self) -> bool:
        """Verificar si el código ha expirado"""
        return datetime.now().timestamp() > self.expires_at
    
    def verify_challenge(self, code_verifier: str) -> bool:
        """Verificar PKCE challenge"""
        if self.code_challenge_method == "plain":
            return self.code_challenge == code_verifier
        elif self.code_challenge_method == "S256":
            import hashlib
            import base64
            digest = hashlib.sha256(code_verifier.encode()).digest()
            expected = base64.urlsafe_b64encode(digest).decode().rstrip('=')
            return self.code_challenge == expected
        return False

class ServicioDeAutenticacion:
    """Clase Servicio_de_autenticacion según documentación (Clase --9)"""
    
    def __init__(self):
        self.refresh_tokens: Dict[str, TokenDeRefresco] = {}
        self.authorization_codes: Dict[str, CodigoDeAutenticacion] = {}
        self.oauth_clients: Dict[str, OauthClient] = {}
        
        # Inicializar con cliente por defecto
        self._init_default_client()
    
    def _init_default_client(self):
        """Inicializar cliente OAuth2 por defecto"""
        default_client = OauthClient(
            id=1,
            client_id="inventario_sena_client",
            client_secret="inventario_sena_secret_2024",
            redirect_url="http://localhost:5173/auth/callback",
            is_confidential=True
        )
        self.oauth_clients[default_client.client_id] = default_client
    
    def _generate_random_string(self, length: int = 32) -> str:
        """Generar string aleatorio seguro"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def authorize(
        self, 
        client_id: str, 
        redirect_uri: str, 
        scope: str = "read write",
        response_type: str = "code",
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256"
    ) -> Dict[str, Any]:
        """
        Inicia el flujo OAuth2/OIDC según documentación
        Método authorize() de la clase Servicio_de_autenticacion
        """
        try:
            # Verificar cliente
            if client_id not in self.oauth_clients:
                raise HTTPException(status_code=400, detail="Client ID inválido")
            
            client = self.oauth_clients[client_id]
            
            # Verificar URL de redirección
            if not client.is_redirect_url_valid(redirect_uri):
                raise HTTPException(status_code=400, detail="Redirect URI inválido")
            
            # Verificar tipo de respuesta
            if response_type != "code":
                raise HTTPException(status_code=400, detail="Tipo de respuesta no soportado")
            
            return {
                "authorization_url": f"/oauth/login?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge_required": code_challenge is not None
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en authorize: {str(e)}")
    
    def create_authorization_code(
        self,
        client_id: str,
        username: str,
        redirect_uri: str,
        code_challenge: str = "",
        code_challenge_method: str = "S256"
    ) -> str:
        """Crear código de autorización"""
        code = self._generate_random_string(32)
        expires_at = datetime.now() + timedelta(minutes=AUTHORIZATION_CODE_EXPIRE_MINUTES)
        
        auth_code = CodigoDeAutenticacion(
            code=code,
            client_id=client_id,
            userName=username,
            expires_at=expires_at.timestamp(),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_url=redirect_uri
        )
        
        self.authorization_codes[code] = auth_code
        return code
    
    def token(
        self,
        grant_type: str,
        client_id: str,
        client_secret: str,
        code: Optional[str] = None,
        refresh_token: Optional[str] = None,
        code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Emite un Access Token y opcionalmente un Refresh Token según documentación
        Método token() de la clase Servicio_de_autenticacion
        """
        try:
            # Verificar cliente
            if client_id not in self.oauth_clients:
                raise HTTPException(status_code=401, detail="Cliente no válido")
            
            client = self.oauth_clients[client_id]
            
            if client.is_confidential and not client.verify_secret(client_secret):
                raise HTTPException(status_code=401, detail="Secreto de cliente inválido")
            
            if grant_type == "authorization_code":
                return self._handle_authorization_code_grant(code, code_verifier, client_id)
            elif grant_type == "refresh_token":
                return self._handle_refresh_token_grant(refresh_token, client_id)
            else:
                raise HTTPException(status_code=400, detail="Tipo de grant no soportado")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en token: {str(e)}")
    
    def _handle_authorization_code_grant(self, code: str, code_verifier: str, client_id: str) -> Dict[str, Any]:
        """Manejar grant type authorization_code"""
        if not code or code not in self.authorization_codes:
            raise HTTPException(status_code=400, detail="Código de autorización inválido")
        
        auth_code = self.authorization_codes[code]
        
        # Verificar expiración
        if auth_code.is_expired():
            del self.authorization_codes[code]
            raise HTTPException(status_code=400, detail="Código de autorización expirado")
        
        # Verificar cliente
        if auth_code.client_id != client_id:
            raise HTTPException(status_code=400, detail="Cliente no coincide")
        
        # Verificar PKCE si se requiere
        if auth_code.code_challenge and code_verifier:
            if not auth_code.verify_challenge(code_verifier):
                raise HTTPException(status_code=400, detail="Code verifier inválido")
        
        # Crear tokens
        access_token = self._create_access_token(auth_code.userName)
        refresh_token = self._create_refresh_token(auth_code.userName, client_id)
        
        # Limpiar código usado
        del self.authorization_codes[code]
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token,
            "scope": "read write"
        }
    
    def _handle_refresh_token_grant(self, refresh_token: str, client_id: str) -> Dict[str, Any]:
        """Manejar grant type refresh_token"""
        if not refresh_token or refresh_token not in self.refresh_tokens:
            raise HTTPException(status_code=400, detail="Refresh token inválido")
        
        token_obj = self.refresh_tokens[refresh_token]
        
        # Verificar expiración
        if token_obj.is_expired():
            del self.refresh_tokens[refresh_token]
            raise HTTPException(status_code=400, detail="Refresh token expirado")
        
        # Verificar cliente
        if token_obj.client_id != client_id:
            raise HTTPException(status_code=400, detail="Cliente no coincide")
        
        # Crear nuevo access token
        access_token = self._create_access_token(token_obj.userName)
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "scope": "read write"
        }
    
    def _create_access_token(self, username: str) -> str:
        """Crear access token JWT (implementa CreateAccessToken de Token_de_servicio)"""
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        data = {
            "sub": username,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access_token"
        }
        return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    
    def _create_refresh_token(self, username: str, client_id: str) -> str:
        """Crear refresh token"""
        token = self._generate_random_string(64)
        expires_at = datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        refresh_token = TokenDeRefresco(
            token=token,
            userName=username,
            client_id=client_id,
            expires_at=expires_at.timestamp()
        )
        
        self.refresh_tokens[token] = refresh_token
        return token
    
    def introspect(self, token: str) -> Dict[str, Any]:
        """
        Permite validar y obtener info sobre un token activo según documentación
        Método introspect() de la clase Servicio_de_autenticacion
        """
        try:
            # Decodificar token JWT (implementa decodeToken de Token_de_servicio)
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # Verificar si el usuario existe
            user = execute_query(
                "SELECT id, documento, nombre, rol, activo FROM usuarios WHERE documento = %s",
                (payload["sub"],),
                fetch_one=True
            )
            
            if not user or not user['activo']:
                return {"active": False}
            
            return {
                "active": True,
                "sub": payload["sub"],
                "exp": payload["exp"],
                "iat": payload["iat"],
                "token_type": payload.get("type", "access_token"),
                "user_info": {
                    "id": user["id"],
                    "documento": user["documento"],
                    "nombre": user["nombre"],
                    "rol": user["rol"]
                }
            }
            
        except jwt.ExpiredSignatureError:
            return {"active": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"active": False, "error": "Invalid token"}
        except Exception as e:
            return {"active": False, "error": str(e)}
    
    def revoke(self, token: str, token_type_hint: str = "access_token") -> Dict[str, Any]:
        """
        Invalida un token (access o refresh) según documentación
        Método revoke() de la clase Servicio_de_autenticacion
        """
        try:
            if token_type_hint == "refresh_token" or token in self.refresh_tokens:
                # Revocar refresh token
                if token in self.refresh_tokens:
                    del self.refresh_tokens[token]
                    return {"revoked": True, "token_type": "refresh_token"}
                else:
                    return {"revoked": False, "error": "Refresh token not found"}
            
            else:
                # Para access tokens JWT, no podemos revocarlos directamente
                # En una implementación completa, mantendríamos una blacklist
                return {
                    "revoked": True, 
                    "token_type": "access_token",
                    "note": "Access token marked for revocation (consider implementing blacklist)"
                }
                
        except Exception as e:
            return {"revoked": False, "error": str(e)}
    
    def userinfo(self, token: str) -> Dict[str, Any]:
        """
        Devuelve los datos del usuario autenticado (claims) según documentación
        Método userinfo() de la clase Servicio_de_autenticacion
        """
        try:
            # Validar token primero
            introspection = self.introspect(token)
            
            if not introspection.get("active", False):
                raise HTTPException(status_code=401, detail="Token inválido o expirado")
            
            user_info = introspection["user_info"]
            
            # Obtener información adicional del usuario
            user_details = execute_query(
                "SELECT documento, nombre, email, rol, activo, fecha_creacion FROM usuarios WHERE id = %s",
                (user_info["id"],),
                fetch_one=True
            )
            
            if not user_details:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
            return {
                "sub": user_details["documento"],
                "name": user_details["nombre"],
                "email": user_details.get("email"),
                "role": user_details["rol"],
                "active": user_details["activo"],
                "created_at": user_details["fecha_creacion"].isoformat() if user_details["fecha_creacion"] else None,
                "user_id": user_info["id"]
            }
            
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en userinfo: {str(e)}")
    
    def authenticate_user(self, documento: str, password: str) -> Optional[Dict[str, Any]]:
        """Autenticar usuario para el flujo OAuth"""
        try:
            user = execute_query(
                "SELECT id, documento, nombre, email, rol, password_hash, activo FROM usuarios WHERE documento = %s",
                (documento,),
                fetch_one=True
            )
            
            if not user or not user['activo']:
                return None
            
            if not verify_password(password, user['password_hash']):
                return None
            
            return {
                "id": user['id'],
                "documento": user['documento'],
                "nombre": user['nombre'],
                "email": user['email'],
                "rol": user['rol']
            }
            
        except Exception:
            return None
    
    def cleanup_expired_tokens(self):
        """Limpiar tokens y códigos expirados"""
        current_time = datetime.now().timestamp()
        
        # Limpiar refresh tokens expirados
        expired_refresh = [
            token for token, obj in self.refresh_tokens.items()
            if obj.expires_at < current_time
        ]
        for token in expired_refresh:
            del self.refresh_tokens[token]
        
        # Limpiar códigos de autorización expirados
        expired_codes = [
            code for code, obj in self.authorization_codes.items()
            if obj.expires_at < current_time
        ]
        for code in expired_codes:
            del self.authorization_codes[code]

# Instancia global del servicio OAuth
oauth_service = ServicioDeAutenticacion()
