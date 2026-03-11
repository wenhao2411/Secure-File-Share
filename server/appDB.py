import sqlite3
from models import User,File,FilePermission
class Database:
    def __init__(self,db_path="secureshare.db"):
        self.db_path = db_path
        self.init_db()
        pass

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Enable foreign keys
        cursor.execute("PRAGMA foreign_keys = ON;")

        # -------------------------
        # USERS TABLE
        # -------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            public_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        );
        """)

        # -------------------------
        # FILES TABLE
        # -------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            stored_filename TEXT UNIQUE NOT NULL,
            owner_id TEXT NOT NULL,
            owner TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            signature BLOB NULL,
            auth_tag BLOB NOT NULL,
            mime_type TEXT,
            gcm_nonce BLOB NOT NULL,
            created_at TEXT NOT NULL,
            modified_at TEXT,
            last_modified_by TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (last_modified_by) REFERENCES users(id)
        );
        """)

        # -------------------------
        # FILE PERMISSIONS TABLE
        # -------------------------
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_permissions (
            file_id TEXT,
            user_id TEXT,
            encrypted_file_key BLOB NOT NULL,
            ephemeral_public_key TEXT NOT NULL,
            nonce BLOB NOT NULL,
            salt BLOB NOT NULL,
            info BLOB NOT NULL,
            key_auth_tag BLOB NOT NULL,
            granted_by TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            PRIMARY KEY (file_id, user_id),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (granted_by) REFERENCES users(id)
        );
        """)

        conn.commit()
        conn.close()
        print("[✓] Database initialized")
    
    def add_user(self,user:User):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO users (id, username, password_hash, public_key, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user.id,
                user.username,
                user.password_hash,
                user.public_key,
                user.created_at.isoformat(),
                user.last_login.isoformat() if user.last_login else None
            ))
            conn.commit()
            conn.close()
            return {"success":True}
        except sqlite3.IntegrityError:
            return {"success": False, "error": "Username already exists"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def add_file(self,file:File):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO files (id, filename, stored_filename, owner_id, owner, file_size,
                                signature, auth_tag, mime_type, gcm_nonce, created_at, modified_at, last_modified_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file.id,
                file.filename,
                file.stored_filename,
                file.owner_id,
                file.owner,
                file.file_size,
                file.signature,
                file.auth_tag,
                file.mime_type,
                file.gcm_nonce,
                file.created_at.isoformat(),
                file.modified_at.isoformat(),
                file.modified_by       
            ))
            conn.commit()
            conn.close()
            return {"success":True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def add_file_permission(self,file_permission:FilePermission):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO file_permissions (file_id, user_id, encrypted_file_key,
                                            ephemeral_public_key, nonce, salt, info, key_auth_tag,
                                            granted_by, granted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_permission.file_id,
                file_permission.user_id,
                file_permission.encrypted_file_key,
                file_permission.ephemeral_public_key,
                file_permission.nonce,
                file_permission.salt,
                file_permission.info,
                file_permission.key_auth_tag,
                file_permission.granted_by,
                file_permission.granted_at.isoformat() 
            ))
            conn.commit()
            conn.close() 
            return {"success":True}
        except Exception as e:
            return {"success": False, "error": str(e)}


    def get_user_by_name(self, username: str):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE username = ?",(username,))

            row = cursor.fetchone()
            conn.close()

            if row is None:
                return {"success": False, "error": "User not found"}

            user_data = dict(row)
            username = user_data["username"]
            password_hash = user_data["password_hash"]
            public_key = user_data["public_key"]
            created_at = user_data["created_at"]
            last_login = user_data["last_login"]
            user_id = user_data["id"]
            user = User(username,password_hash,public_key,created_at,last_login,user_id)

            return {"success": True, "user": user}

        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_user(self, user_id: str, **fields):
        if not fields:
            return {"success": False, "error": "No fields provided"}

        allowed_fields = {"username", "password_hash", "public_key", "last_login"}
        updates = []
        values = []

        for key, value in fields.items():
            if key not in allowed_fields:
                return {"success": False, "error": f"Invalid field: {key}"}
            updates.append(f"{key} = ?")
            values.append(value)

        values.append(user_id)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                values
            )

            if cursor.rowcount == 0:
                conn.close()
                return {"success": False, "error": "User not found"}

            conn.commit()
            conn.close()

            return {"success": True, "message": "User updated"}

        except sqlite3.IntegrityError as e:
            return {"success": False, "error": "Username already exists"}

        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_file_by_name(self, stored_name: str):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM files WHERE stored_filename = ?",(stored_name,))

            row = cursor.fetchone()
            conn.close()

            if row is None:
                return {"success": False, "error": "File not found"}

            file_data = dict(row)

            return {"success": True, "file_data": file_data }

        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_file_permission_by_id(self, file_id: str, user_id:str):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM file_permissions WHERE file_id = ? AND user_id = ?",(file_id, user_id,))

            row = cursor.fetchone()
            conn.close()

            if row is None:
                return {"success": False, "error": "No file permission"}

            file_permission = dict(row)

            return {"success": True, "file_permission": file_permission }

        except Exception as e:
            return {"success": False, "error": str(e)}
    

    def get_user_files_id(self, user_id:str):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT file_id FROM file_permissions WHERE user_id = ?",(user_id,))

            list_of_row = cursor.fetchall()
            conn.close()

            if len(list_of_row) == 0:
                return {"success": False, "error": "Does not exist"}

            files_id = [row[0] for row in list_of_row]

            return {"success": True, "files_id": files_id}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_all_files_by_ids(self, files_id:list):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            placeholders = ','.join(['?' for _ in files_id])
            query = f"SELECT filename, owner, file_size, modified_at, last_modified_by FROM files WHERE id IN ({placeholders})"

            cursor.execute(query,files_id)

            list_of_row = cursor.fetchall()
            conn.close()

            if len(list_of_row) == 0:
                return {"success": False, "error": "Does not exist"}

            files_data = [dict(row) for row in list_of_row]

            return {"success": True, "files_data": files_data}

        except Exception as e:
            return {"success": False, "error": str(e)}

