from database import get_db_connection
import psycopg2

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(50),
            last_name VARCHAR(50),
            middle_name VARCHAR(50),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) UNIQUE NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id SERIAL PRIMARY KEY,
            resource VARCHAR(100) NOT NULL,
            action VARCHAR(50) NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INT REFERENCES roles(id),
            permission_id INT REFERENCES permissions(id),
            UNIQUE (role_id, permission_id)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INT REFERENCES users(id),
            role_id INT REFERENCES roles(id),
            UNIQUE (user_id, role_id)
        );
    """)

    from auth import hash_password
    admin_password = hash_password("admin123")
    user_password = hash_password("user123")

    cursor.execute("""
        INSERT INTO users (first_name, last_name, email, password_hash, is_active)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (email) DO NOTHING;
    """, ("Admin", "User", "admin@example.com", admin_password, True))

    cursor.execute("""
        INSERT INTO users (first_name, last_name, email, password_hash, is_active)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (email) DO NOTHING;
    """, ("Regular", "User", "user@example.com", user_password, True))

    cursor.execute("""
        INSERT INTO roles (name)
        VALUES (%s), (%s)
        ON CONFLICT (name) DO NOTHING;
    """, ("admin", "user"))

    cursor.execute("""
        INSERT INTO permissions (resource, action)
        VALUES (%s, %s), (%s, %s), (%s, %s), (%s, %s)
        ON CONFLICT (resource, action) DO NOTHING;
    """, ("admin", "manage_roles", "document", "read", "document", "delete", "comment", "read"))

    cursor.execute("""
        INSERT INTO user_roles (user_id, role_id)
        SELECT u.id, r.id FROM users u, roles r
        WHERE u.email = %s AND r.name = %s
        ON CONFLICT (user_id, role_id) DO NOTHING;
    """, ("admin@example.com", "admin"))

    cursor.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id FROM roles r, permissions p
        WHERE r.name = %s AND p.resource = %s AND p.action = %s
        ON CONFLICT (role_id, permission_id) DO NOTHING;
    """, ("admin", "admin", "manage_roles"))

    cursor.execute("""
        INSERT INTO user_roles (user_id, role_id)
        SELECT u.id, r.id FROM users u, roles r
        WHERE u.email = %s AND r.name = %s
        ON CONFLICT (user_id, role_id) DO NOTHING;
    """, ("user@example.com", "user"))

    cursor.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id FROM roles r, permissions p
        WHERE r.name = %s AND p.resource = %s AND p.action = %s
        ON CONFLICT (role_id, permission_id) DO NOTHING;
    """, ("user", "document", "read"))

    cursor.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id FROM roles r, permissions p
        WHERE r.name = %s AND p.resource = %s AND p.action = %s
        ON CONFLICT (role_id, permission_id) DO NOTHING;
    """, ("user", "comment", "read"))

    conn.commit()
    cursor.close()
    conn.close()
    print("Database initialized with test data.")

if __name__ == "__main__":
    init_db()