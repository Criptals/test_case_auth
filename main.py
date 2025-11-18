from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth import authenticate_user, register_user, get_user_profile, update_user_profile, delete_user, create_access_token
from rbac import check_permission, create_role, create_permission, assign_role_to_user, assign_permission_to_role
from schemas import UserCreate, UserUpdate, Token
from typing import Optional
import uvicorn

app = FastAPI(title="Custom Auth System")
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    from config import SECRET_KEY, ALGORITHM
    import jwt
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        from database import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = %s AND is_active = TRUE", (user_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            raise HTTPException(status_code=401, detail="User is inactive")
        cursor.close()
        conn.close()
        return user_id
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


@app.post("/register", status_code=201)
def register(user: UserCreate):
    user_id = register_user(user)
    return {"message": "User registered", "user_id": user_id}


@app.post("/login", response_model=Token)
def login(email: str, password: str):
    user_id = authenticate_user(email, password)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"user_id": user_id})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/profile")
def get_profile(user_id: int = Depends(get_current_user)):
    return get_user_profile(user_id)


@app.put("/profile")
def update_profile(user_update: UserUpdate, user_id: int = Depends(get_current_user)):
    update_user_profile(user_id, user_update.model_dump(exclude_unset=True))
    return {"message": "Profile updated"}


@app.delete("/profile")
def remove_profile(user_id: int = Depends(get_current_user)):
    delete_user(user_id)
    return {"message": "Account deactivated"}


def require_admin(user_id: int = Depends(get_current_user)):
    from rbac import check_permission
    if not check_permission(user_id, "admin", "manage_roles"):
        raise HTTPException(status_code=403, detail="Forbidden: Admin access required")
    return user_id


@app.post("/admin/roles")
def admin_create_role(name: str, user_id: int = Depends(require_admin)):
    role_id = create_role(name)
    return {"message": "Role created", "role_id": role_id}


@app.post("/admin/permissions")
def admin_create_permission(resource: str, action: str, user_id: int = Depends(require_admin)):
    perm_id = create_permission(resource, action)
    return {"message": "Permission created", "permission_id": perm_id}


@app.post("/admin/assign-role")
def admin_assign_role(user_id_to_assign: int, role_id: int, admin_user_id: int = Depends(require_admin)):
    assign_role_to_user(user_id_to_assign, role_id)
    return {"message": "Role assigned"}


@app.post("/admin/assign-permission")
def admin_assign_permission(role_id: int, permission_id: int, admin_user_id: int = Depends(require_admin)):
    assign_permission_to_role(role_id, permission_id)
    return {"message": "Permission assigned"}


@app.get("/documents")
def get_documents(user_id: int = Depends(get_current_user)):
    if not check_permission(user_id, "document", "read"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"data": "List of documents"}


@app.delete("/documents/{doc_id}")
def delete_document(doc_id: int, user_id: int = Depends(get_current_user)):
    if not check_permission(user_id, "document", "delete"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"message": f"Document {doc_id} deleted"}


@app.get("/comments")
def get_comments(user_id: int = Depends(get_current_user)):
    if not check_permission(user_id, "comment", "read"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"data": "List of comments"}


@app.get("/users")
def get_users_list(user_id: int = Depends(get_current_user)):
    if not check_permission(user_id, "user", "read"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"data": "List of users"}


if __name__ == "__main__":
    import os
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)