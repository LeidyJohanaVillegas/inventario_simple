"""
Router para endpoints OAuth2 según la documentación del proyecto
Implementa los endpoints del Servicio_de_autenticacion
"""

from fastapi import APIRouter, HTTPException, Depends, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from typing import Optional
from pydantic import BaseModel

from ..services.oauth_service import oauth_service
from ..models import MessageResponse

router = APIRouter()

class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str
    code: Optional[str] = None
    refresh_token: Optional[str] = None
    code_verifier: Optional[str] = None

class AuthorizeRequest(BaseModel):
    client_id: str
    redirect_uri: str
    scope: str = "read write"
    response_type: str = "code"
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: str = "S256"

@router.get("/authorize")
async def authorize_endpoint(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read write"),
    response_type: str = Query("code"),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: str = Query("S256")
):
    """
    Endpoint de autorización OAuth2
    Implementa el método authorize() del Servicio_de_autenticacion
    """
    try:
        auth_data = oauth_service.authorize(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            response_type=response_type,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        
        # Redirigir a página de login con parámetros
        login_url = f"/oauth/login?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state or ''}"
        return RedirectResponse(url=login_url, status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en authorize: {str(e)}")

@router.get("/login", response_class=HTMLResponse)
async def login_page(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read write"),
    state: Optional[str] = Query(None)
):
    """Página de login para OAuth2"""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sistema de Inventario - Login OAuth2</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 400px;
                width: 100%;
            }}
            h1 {{
                color: #333;
                margin-bottom: 30px;
                font-size: 2em;
            }}
            .form-group {{
                margin-bottom: 20px;
                text-align: left;
            }}
            label {{
                display: block;
                margin-bottom: 8px;
                color: #555;
                font-weight: bold;
            }}
            input {{
                width: 100%;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 16px;
                box-sizing: border-box;
            }}
            input:focus {{
                border-color: #667eea;
                outline: none;
                box-shadow: 0 0 10px rgba(102, 126, 234, 0.2);
            }}
            button {{
                width: 100%;
                padding: 15px;
                background: linear-gradient(45deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-top: 10px;
            }}
            button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }}
            .client-info {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 4px solid #667eea;
            }}
            .error {{
                color: #dc3545;
                margin-top: 10px;
                padding: 10px;
                background: #f8d7da;
                border-radius: 5px;
                display: none;
            }}
            .success {{
                color: #155724;
                margin-top: 10px;
                padding: 10px;
                background: #d4edda;
                border-radius: 5px;
                display: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Autorización OAuth2</h1>
            
            <div class="client-info">
                <p><strong>Cliente:</strong> {client_id}</p>
                <p><strong>Permisos:</strong> {scope}</p>
                <p><strong>Redirección:</strong> {redirect_uri}</p>
            </div>
            
            <form id="loginForm">
                <div class="form-group">
                    <label for="documento">Documento:</label>
                    <input type="text" id="documento" name="documento" required placeholder="Número de documento">
                </div>
                
                <div class="form-group">
                    <label for="password">Contraseña:</label>
                    <input type="password" id="password" name="password" required placeholder="Contraseña">
                </div>
                
                <button type="submit">Autorizar Acceso</button>
                
                <div id="error" class="error"></div>
                <div id="success" class="success"></div>
            </form>
        </div>

        <script>
            document.getElementById('loginForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                
                const errorDiv = document.getElementById('error');
                const successDiv = document.getElementById('success');
                const documento = document.getElementById('documento').value;
                const password = document.getElementById('password').value;
                
                errorDiv.style.display = 'none';
                successDiv.style.display = 'none';
                
                try {{
                    const response = await fetch('/oauth/authenticate', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            documento: documento,
                            password: password,
                            client_id: '{client_id}',
                            redirect_uri: '{redirect_uri}',
                            scope: '{scope}',
                            state: '{state or ""}'
                        }})
                    }});
                    
                    const result = await response.json();
                    
                    if (response.ok && result.redirect_url) {{
                        successDiv.textContent = 'Autenticación exitosa. Redirigiendo...';
                        successDiv.style.display = 'block';
                        
                        setTimeout(() => {{
                            window.location.href = result.redirect_url;
                        }}, 1000);
                    }} else {{
                        errorDiv.textContent = result.detail || 'Error de autenticación';
                        errorDiv.style.display = 'block';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Error de conexión: ' + error.message;
                    errorDiv.style.display = 'block';
                }}
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.post("/authenticate")
async def authenticate_user(
    documento: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("read write"),
    state: Optional[str] = Form(None)
):
    """Autenticar usuario y generar código de autorización"""
    try:
        # Autenticar usuario
        user = oauth_service.authenticate_user(documento, password)
        
        if not user:
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        
        # Crear código de autorización
        auth_code = oauth_service.create_authorization_code(
            client_id=client_id,
            username=documento,
            redirect_uri=redirect_uri
        )
        
        # Construir URL de redirección
        redirect_url = f"{redirect_uri}?code={auth_code}"
        if state:
            redirect_url += f"&state={state}"
        
        return {"redirect_url": redirect_url, "message": "Autenticación exitosa"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error de autenticación: {str(e)}")

@router.post("/token")
async def token_endpoint(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None)
):
    """
    Endpoint de token OAuth2
    Implementa el método token() del Servicio_de_autenticacion
    """
    try:
        token_response = oauth_service.token(
            grant_type=grant_type,
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            refresh_token=refresh_token,
            code_verifier=code_verifier
        )
        
        return token_response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en token: {str(e)}")

@router.post("/introspect")
async def introspect_endpoint(
    token: str = Form(...)
):
    """
    Endpoint de introspección de token
    Implementa el método introspect() del Servicio_de_autenticacion
    """
    try:
        introspection = oauth_service.introspect(token)
        return introspection
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en introspect: {str(e)}")

@router.post("/revoke")
async def revoke_endpoint(
    token: str = Form(...),
    token_type_hint: str = Form("access_token")
):
    """
    Endpoint de revocación de token
    Implementa el método revoke() del Servicio_de_autenticacion
    """
    try:
        revocation = oauth_service.revoke(token, token_type_hint)
        return revocation
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en revoke: {str(e)}")

@router.get("/userinfo")
async def userinfo_endpoint(
    authorization: str = Query(..., description="Bearer token")
):
    """
    Endpoint de información de usuario
    Implementa el método userinfo() del Servicio_de_autenticacion
    """
    try:
        # Extraer token del header Authorization
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Token Bearer requerido")
        
        token = authorization.replace("Bearer ", "")
        user_info = oauth_service.userinfo(token)
        return user_info
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en userinfo: {str(e)}")

@router.post("/cleanup")
async def cleanup_expired_tokens():
    """Endpoint para limpiar tokens expirados (solo para administradores)"""
    try:
        oauth_service.cleanup_expired_tokens()
        return MessageResponse(
            message="Tokens expirados limpiados exitosamente",
            success=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en cleanup: {str(e)}")

@router.get("/clients")
async def get_oauth_clients():
    """Obtener información de clientes OAuth registrados"""
    try:
        clients = []
        for client_id, client in oauth_service.oauth_clients.items():
            clients.append({
                "client_id": client.client_id,
                "redirect_url": client.redirect_url,
                "is_confidential": client.is_confidential
            })
        
        return {"clients": clients}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener clientes: {str(e)}")

@router.get("/status")
async def oauth_status():
    """Estado del servicio OAuth2"""
    try:
        status = {
            "service_active": True,
            "total_clients": len(oauth_service.oauth_clients),
            "active_refresh_tokens": len(oauth_service.refresh_tokens),
            "pending_auth_codes": len(oauth_service.authorization_codes),
            "endpoints": [
                "/oauth/authorize",
                "/oauth/token", 
                "/oauth/introspect",
                "/oauth/revoke",
                "/oauth/userinfo"
            ]
        }
        
        return status
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estado: {str(e)}")
