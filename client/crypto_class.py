from typing import Union
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature, InvalidTag
import os
import bcrypt
import base64


class CryptoClass:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
        self.curve_name = "P-256" 
    
    def generate_user_keypair(self, password=None):
        # Generate private key object
        private_key_obj = ec.generate_private_key(self.curve)
        
        # Get public key object
        public_key_obj = private_key_obj.public_key()
        
        # Serialize public key to PEM for server storage
        public_key_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Serialize private key to PEM
        private_key_pem = self.serialize_private_key(private_key_obj,password)
        
        return {
            'private_key_pem': private_key_pem,
            'public_key_pem': public_key_pem
        }
    
    def public_key_pem_to_obj(self, public_key_pem):
        try:
            public_key_obj = load_pem_public_key(
                public_key_pem.encode('utf-8')
            )
            return public_key_obj
        except Exception as e:
            print(f"Error converting public key: {e}")
            return None
    
    def private_key_pem_to_obj(self, private_key_pem, password=None):
        try:
            if password:
                private_key_obj = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=password.encode('utf-8')
                )
            else:
                private_key_obj = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None
                )
            return private_key_obj
        except Exception as e:
            print(f"Error converting private key: {e}")
            return None
    
    def serialize_private_key(self, private_key_obj, password=None):
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        return private_key_pem.decode('utf-8')
    
    def hash_password(self,password,salt_rounds=12):
        salt = bcrypt.gensalt(salt_rounds)  
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash
    
    def check_password(self, password, password_hash):
        return bcrypt.checkpw(password.encode('utf-8'),password_hash)
    
    
    
    def ecies_encrypt_key(self, recipient_public_key, symmetric_key: bytes):
        # 1. Generate ephemeral EC key pair
        ephemeral_private = ec.generate_private_key(self.curve)
        ephemeral_public = ephemeral_private.public_key()

        # 2. Perform ECDH to derive shared secret
        shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)

        # 3. Derive AES key from shared secret using HKDF
        salt = os.urandom(16)
        info = b'ecies key wrap'
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_secret)

        # 4. Encrypt the symmetric key with derived AES key (AES-GCM)
        encryption_result = self.aes_gcm_encrypt_data(symmetric_key, derived_key)
        if encryption_result["success"]:
            encrypted_key = encryption_result["encrypted_data"]
            nonce = encryption_result["nonce"]
            tag = encryption_result["auth_tag"]
        else:
            return None
        # 5. Serialize ephemeral public key to PEM for storage
        ephemeral_public_pem = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return {
            'encrypted_key': encrypted_key,
            'ephemeral_public_key': ephemeral_public_pem,
            'nonce': nonce,
            'salt': salt,
            'info': info,
            'tag': tag
        }
    
    def ecies_decrypt_key(self, recipient_private_key, encrypted_key: bytes, ephemeral_public_pem: str, nonce: bytes, salt: bytes, info: bytes, tag: bytes):
        ephemeral_public = self.public_key_pem_to_obj(ephemeral_public_pem)

        shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(shared_secret)

        # Decrypt AES key
        decryption_result = self.aes_gcm_decrypt_data(encrypted_key, derived_key, nonce, tag)
        if decryption_result["success"]:
            return decryption_result["decrypted_data"]
        else:
            return None
        
    def get_sha256_digest(self,data: Union[str, bytes]):
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            raise TypeError("data must be string or bytes")
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return(digest.finalize())
    
    def sign_with_ecdsa(self,private_key,data:  Union[str, bytes]):
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            raise TypeError("data must be string or bytes")
        
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature
    
    def verify_ecdsa(self,public_key,signature, data: Union[str, bytes]):
        try :
            if isinstance(data, str):
                data = data.encode('utf-8')
            elif not isinstance(data, bytes):
                raise TypeError("data must be string or bytes")
            
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature :
            return False

    
    def b64encode(self, data: bytes):
        return base64.b64encode(data).decode('utf-8')

    def b64decode(self, data_str: str):
        return base64.b64decode(data_str.encode('utf-8'))
    
    def aes_gcm_encrypt_data(self, data: bytes, key: bytes = None):
        try:
            nonce = os.urandom(12)
            if key is None:
                key = os.urandom(32)
            elif len(key) != 32:
                return {"success": False, "error": f"Invalid key length: {len(key)} bytes"}

            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            ).encryptor()
            
            
            chunk_size = 64 * 1024
            if data:
                total_chunk = len(data) // chunk_size
                if len(data) % chunk_size:
                    total_chunk += 1
            else:
                total_chunk = 0
            
            encrypted_data_parts = []
            for chunk_num in range(total_chunk):
                start = chunk_num * chunk_size
                end = min(start + chunk_size, len(data))
                chunk = data[start:end]
                encrypted_chunk = encryptor.update(chunk)
                encrypted_data_parts.append(encrypted_chunk)

            encryptor.finalize()
            tag = encryptor.tag 

            encrypted_data = b''.join(encrypted_data_parts)
            return {"success": True, "encrypted_data": encrypted_data, "auth_tag":tag, "nonce": nonce, "key": key }
        except Exception as e:
            return {"success": False, "error":str(e)}

    def aes_gcm_decrypt_data(self, encrypted_data: bytes, key: bytes, nonce: bytes, tag: bytes):
        try:
            if len(key) != 32:
                return {"success": False, "error": f"Invalid key length: {len(key)} bytes"}
            
            if len(nonce) != 12:
                return {"success": False, "error": f"Nonce must be 12 bytes, got {len(nonce)}"}
            
            if len(tag) != 16:
                return {"success": False, "error": f"Tag must be 16 bytes, got {len(tag)}"}
            
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()

            chunk_size = 64 * 1024
            if encrypted_data:
                total_chunk = len(encrypted_data) // chunk_size
                if len(encrypted_data) % chunk_size:
                    total_chunk += 1
            else:
                total_chunk = 0
            
            decrypted_data_parts = []
            for chunk_num in range(total_chunk):
                start = chunk_num * chunk_size
                end = min(start + chunk_size, len(encrypted_data))
                chunk = encrypted_data[start:end]
                decrypted_chunk = decryptor.update(chunk)
                decrypted_data_parts.append(decrypted_chunk)

            # This will raise InvalidTag if authentication fails
            decryptor.finalize()
            decrypted_data = b''.join(decrypted_data_parts)

            return {"success": True, "decrypted_data": decrypted_data}
            
        except InvalidTag as e:
            return {"success": False, "error": "Authentication failed: Data may be corrupted or tampered"}
        except Exception as e:
            return {"success": False, "error": f"Decryption failed: {str(e)}"}