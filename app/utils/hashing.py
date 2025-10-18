from passlib.context import CryptContext

# Cambiamos a Argon2 (sin límite de longitud y más seguro que bcrypt)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """
    Devuelve el hash seguro del password usando Argon2.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si el password plano coincide con el hash almacenado.
    """
    return pwd_context.verify(plain_password, hashed_password)
