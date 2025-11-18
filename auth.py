import bcrypt
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from config import SECRET_KEY, ALGORITHM
from database import get_db_connection
from schemas import UserCreate
import psycopg2


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(email: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT id, password_hash FROM users
            WHERE email = %s AND is_active = TRUE
        """, (email,))
        user = cursor.fetchone()
        if not user or not verify_password(password, user[1]):
            return None
        return user[0]
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def register_user(user_data: UserCreate):
    if user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    conn = get_db_connection()
    cursor = conn.cursor()

    hashed = hash_password(user_data.password)
    try:
        cursor.execute("""
            INSERT INTO users (first_name, last_name, middle_name, email, password_hash)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (
            user_data.first_name,
            user_data.last_name,
            user_data.middle_name,
            user_data.email,
            hashed
        ))
        user_id = cursor.fetchone()[0]
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")
    finally:
        cursor.close()
        conn.close()
    return user_id


def get_user_profile(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT first_name, last_name, middle_name, email
            FROM users
            WHERE id = %s AND is_active = TRUE
        """, (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "first_name": user[0],
            "last_name": user[1],
            "middle_name": user[2],
            "email": user[3]
        }
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def update_user_profile(user_id: int, user_data: dict):
    conn = get_db_connection()
    cursor = conn.cursor()

    updates = []
    values = []
    for field in ["first_name", "last_name", "middle_name"]:
        if user_data.get(field):
            updates.append(f"{field} = %s")
            values.append(user_data[field])

    if not updates:
        cursor.close()
        conn.close()
        return {"message": "No changes"}

    query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
    values.append(user_id)

    try:
        cursor.execute(query, values)
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def delete_user(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET is_active = FALSE WHERE id = %s", (user_id,))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()