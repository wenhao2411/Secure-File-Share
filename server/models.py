import uuid
from datetime import datetime, timezone

class User:
    def __init__(self, username, password_hash, public_key, created_at=None, last_login=None, id=None):
        self.id = id if id else str(uuid.uuid4())
        self.username = username
        self.password_hash = password_hash
        self.public_key = public_key
        self.created_at = created_at if created_at else datetime.now(timezone.utc)
        self.last_login = last_login
    
    

class File:
    def __init__(self, filename, stored_filename, owner_id, owner, file_size, signature, auth_tag,
                 mime_type, gcm_nonce, modified_by, created_at=None, modified_at=None, id=None):
        self.id = id if id else str(uuid.uuid4())
        self.filename = filename
        self.stored_filename = stored_filename
        self.owner_id = owner_id
        self.owner = owner
        self.file_size = file_size
        self.signature = signature 
        self.auth_tag = auth_tag
        self.mime_type = mime_type
        self.gcm_nonce = gcm_nonce
        self.created_at = created_at if created_at else datetime.now(timezone.utc)
        self.modified_at = modified_at if modified_at else datetime.now(timezone.utc)
        self.modified_by = modified_by
    

class FilePermission:
    def __init__(self, file_id, user_id, encrypted_file_key, ephemeral_public_key,
                 nonce, salt, info, key_auth_tag, granted_by, granted_at=None):
        self.file_id = file_id
        self.user_id = user_id
        self.encrypted_file_key = encrypted_file_key
        self.ephemeral_public_key = ephemeral_public_key
        self.nonce = nonce
        self.salt = salt
        self.info = info
        self.key_auth_tag = key_auth_tag
        self.granted_by = granted_by
        self.granted_at = granted_at if granted_at else datetime.now(timezone.utc)\

     