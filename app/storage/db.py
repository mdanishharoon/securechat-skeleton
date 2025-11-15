"""MySQL users table + salted hashing (no chat storage)."""
import os
import secrets
import hashlib
import pymysql
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    """
    Create MySQL database connection.
    Uses individual parameters (not URL) to avoid encoding issues with special chars in password.
    """
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "securechat"),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def init_db():
    """
    Initialize database tables.
    Creates users table with salted password hashing.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_email (email),
                    INDEX idx_username (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            conn.commit()
            print("[+] Database initialized successfully")
            print("[+] Table 'users' created/verified")
    finally:
        conn.close()


def register_user(email: str, username: str, password: str) -> tuple[bool, str]:
    """
    Register a new user with salted password hashing.
    
    Args:
        email: User email (unique)
        username: Username (unique)
        password: Plain password (will be salted and hashed)
        
    Returns:
        (success, message) tuple
    """
    conn = get_connection()
    try:
        # Generate random 16-byte salt
        salt = secrets.token_bytes(16)
        
        # Compute pwd_hash = hex(SHA256(salt || password))
        pwd_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            conn.commit()
            return (True, f"User '{username}' registered successfully")
            
    except pymysql.err.IntegrityError as e:
        if "email" in str(e):
            return (False, "EMAIL_EXISTS: Email already registered")
        elif "username" in str(e):
            return (False, "USERNAME_EXISTS: Username already taken")
        else:
            return (False, f"DB_ERROR: {str(e)}")
    except Exception as e:
        return (False, f"DB_ERROR: {str(e)}")
    finally:
        conn.close()


def authenticate_user(email: str, password: str) -> tuple[bool, str, str]:
    """
    Authenticate user by verifying salted password hash.
    
    Args:
        email: User email
        password: Plain password to verify
        
    Returns:
        (success, message, username) tuple
        If success: (True, "OK", username)
        If failure: (False, error_message, "")
    """
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            
            if not result:
                return (False, "AUTH_FAIL: Invalid email or password", "")
            
            username = result['username']
            salt = result['salt']
            stored_hash = result['pwd_hash']
            
            # Recompute hash with stored salt
            computed_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
            
            if computed_hash == stored_hash:
                return (True, "OK", username)
            else:
                return (False, "AUTH_FAIL: Invalid email or password", "")
                
    except Exception as e:
        return (False, f"DB_ERROR: {str(e)}", "")
    finally:
        conn.close()


def get_user_salt(email: str) -> bytes:
    """
    Retrieve user's salt for client-side password hashing.
    
    Args:
        email: User email
        
    Returns:
        16-byte salt or empty bytes if user not found
    """
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result:
                return result['salt']
            return b""
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument("--init", action="store_true", help="Initialize database tables")
    parser.add_argument("--test", action="store_true", help="Run test registration and login")
    
    args = parser.parse_args()
    
    if args.init:
        init_db()
    elif args.test:
        print("[*] Testing database operations...")
        init_db()
        
        # Test registration
        print("\n[*] Testing registration...")
        success, msg = register_user("test@example.com", "testuser", "testpass123")
        print(f"    Result: {msg}")
        
        # Test authentication
        print("\n[*] Testing authentication...")
        success, msg, username = authenticate_user("test@example.com", "testpass123")
        print(f"    Result: {msg} (username: {username})")
        
        # Test wrong password
        print("\n[*] Testing wrong password...")
        success, msg, username = authenticate_user("test@example.com", "wrongpass")
        print(f"    Result: {msg}")
    else:
        parser.print_help()
