from fastapi import HTTPException, status
from database import get_db_connection
import psycopg2


def assign_role_to_user(user_id: int, role_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_roles (user_id, role_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (user_id, role_id))
        conn.commit()
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def check_permission(user_id: int, resource: str, action: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            SELECT 1 FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = %s AND p.resource = %s AND p.action = %s
        """
        cursor.execute(query, (user_id, resource, action))
        result = cursor.fetchone()
        return result is not None
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def create_role(name: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO roles (name) VALUES (%s) RETURNING id", (name,))
        role_id = cursor.fetchone()[0]
        conn.commit()
        return role_id
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Role already exists")
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def create_permission(resource: str, action: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO permissions (resource, action) VALUES (%s, %s) RETURNING id", (resource, action))
        perm_id = cursor.fetchone()[0]
        conn.commit()
        return perm_id
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Permission already exists")
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()


def assign_permission_to_role(role_id: int, permission_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO role_permissions (role_id, permission_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (role_id, permission_id))
        conn.commit()
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cursor.close()
        conn.close()