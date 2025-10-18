from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.auth.schemas import UserLogin, UserRegister, Token
from app.db.connection import get_connection
from app.utils.hashing import get_password_hash, verify_password
from app.core.security import create_access_token
from psycopg2 import DatabaseError

router = APIRouter()

@router.post("/register")
def register(user: UserRegister):
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM users WHERE email=%s", (user.email,))
        if cur.fetchone():
            return JSONResponse(status_code=400, content={"error": "Email already registered"})

        hashed_pw = get_password_hash(user.password)
        cur.execute(
            "INSERT INTO users (email, hashed_password, name) VALUES (%s, %s, %s)",
            (user.email, hashed_pw, user.name),
        )
        conn.commit()

        return {"message": "User registered successfully"}
    except DatabaseError:
        if conn:
            conn.rollback()
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@router.post("/login", response_model=Token)
def login(user: UserLogin):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE email=%s", (user.email,))
    db_user = cur.fetchone()
    cur.close()
    conn.close()

    if not db_user or not verify_password(user.password, db_user[0]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}
