from jose import jwt
from datetime import datetime, timedelta
from app.core.config import settings

ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=ALGORITHM)
