from pydantic import BaseModel


class LoginRequest(BaseModel):
    documento: str
    password: str


class RegisterRequest(BaseModel):
    rol: str
    tipo_documento: str
    documento: str
    password: str


class LoginResponse(BaseModel):
    message: str
    user_id: int
    documento: str
    rol: str


class RegisterResponse(BaseModel):
    message: str
    user_id: int
    documento: str
    rol: str
