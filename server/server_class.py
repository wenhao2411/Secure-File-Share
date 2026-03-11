import socket
import threading
import json
import os
from session import Session
from models import User,File,FilePermission
from appDB import Database
from crypto_class import CryptoClass
import ssl
from datetime import datetime, timezone
from pathlib import Path


class Server:
    def __init__(self, host='127.0.0.1', port=6767,upload_path="file_storage",ssl_cert_file="server.crt",ssl_key_file="server.key"):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.upload_path = upload_path
        self.db = Database()
        self.crypto = CryptoClass()
        self.ssl_cert_file = ssl_cert_file
        self.ssl_key_file = ssl_key_file
        os.makedirs(self.upload_path, exist_ok=True)
    
    def recv_json(self,conn):
        buffer = ""
        while True:
            data = conn.recv(4096).decode('utf-8')
            if not data:  # connection closed
                return None
            buffer += data
            if "\n" in buffer:  # full message received
                line, buffer = buffer.split("\n", 1)
                return json.loads(line)
            
    def share(self,args,session:Session):
        try:
            if not session.is_authenticated:
                response = {"success":False, "error": "User not authenticated"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return

            if not args["username"] or not args["file_name"]:
                response = {"success": False, "error":"Invalid request"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            if not(args["username"].isalnum()):
                response = {"success": False, "error":"Invalid Username"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            result = self.db.get_user_by_name(args["username"])
            if result["success"]:
                target_user = result["user"]
                target_user_id = target_user.id
                target_user_public_key_pem = target_user.public_key
            else:
                response = {"success": False, "error":result["error"]}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            stored_name = f"{session.user.id}_{args["file_name"]}"
            file = Path(os.path.join(self.upload_path, stored_name))

            result = self.db.get_file_by_name(stored_name)
            if result["success"]:
                file_data = result["file_data"]
            else:
                response = {"success": False, "error":result["error"]}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            if not file.exists():
                response = {"success": False, "error":"File does not exist"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            result = self.db.get_file_permission_by_id(file_data["id"], session.user.id)
            if result["success"]:
                file_permission_data = result["file_permission"]
                file_permission = {"success": True, "user_public_key":target_user_public_key_pem}
                file_permission["ephemeral_public_key"] = file_permission_data["ephemeral_public_key"]
                file_permission["nonce"] = self.crypto.b64encode(file_permission_data["nonce"])
                file_permission["salt"] = self.crypto.b64encode(file_permission_data["salt"])
                file_permission["info"] = self.crypto.b64encode(file_permission_data["info"])
                file_permission["tag"] = self.crypto.b64encode(file_permission_data["key_auth_tag"])
                file_permission["encrypted_key"] = self.crypto.b64encode(file_permission_data["encrypted_file_key"])
                session.conn.sendall((json.dumps(file_permission) + "\n").encode("utf-8"))
            else:
                response = {"success": False, "error":result["error"]}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            client_response = self.recv_json(session.conn)
            if client_response and client_response["success"]:
                encrypted_file_key = self.crypto.b64decode(client_response["encrypted_key"])
                ephemeral_public_key =   client_response["ephemeral_public_key"]
                key_wrap_nonce = self.crypto.b64decode(client_response["nonce"])
                salt = self.crypto.b64decode(client_response["salt"])
                info = self.crypto.b64decode(client_response["info"])
                key_auth_tag = self.crypto.b64decode(client_response["tag"])
                new_permission = FilePermission(file_data["id"],target_user_id,encrypted_file_key,ephemeral_public_key,key_wrap_nonce,salt,info,key_auth_tag,session.user.id)
                result = self.db.add_file_permission(new_permission)
                if result["success"]:
                    response = {"success": True}
                else:
                    response = {"success": False, "error":result["error"]}

                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            else:
                return
            

            
        except Exception as e:
            response = {"success": False, "error": str(e)}
        session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

    def listFiles(self,session:Session):
        try:
            if(session.is_authenticated):
                result = self.db.get_user_files_id(session.user.id)
                if result["success"]:
                    files_id = result["files_id"]
                    file_result = self.db.get_all_files_by_ids(files_id)
                    if file_result["success"]:
                        files_data = file_result["files_data"]
                        response = {"success": True, "files_data": files_data}
                    else:
                        response = {"success": False, "error": file_result["error"]} 
                else:
                    response = {"success": False, "error": result["error"]}        
            else:
                response = {"success": False, "error": "User not authenticated"}
        except Exception as e:
            response = {"success": False, "error": str(e)}
        session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

    
    def sendPublicKey(self,session:Session):
        try:
            if(session.is_authenticated):
                public_key_pem = session.user.public_key
                response = {"success": True, "public_key": public_key_pem}
            else:
                response = {"success": False, "error": "User not authenticated"}
        except Exception as e:
            response = {"success": False, "error": str(e)}

        session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
    
    def fetch(self,args,session:Session):
        try:
            if not session.is_authenticated:
                response = {"success": False, "error":"User not authenticated"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

            if not args["file_owner"] or not args["file_name"]:
                response = {"success": False, "error":"Invalid request"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            if not(args["file_owner"].isalnum()):
                response = {"success": False, "error":"Invalid file owner"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            result = self.db.get_user_by_name(args["file_owner"])
            if result["success"]:
                file_owner = result["user"]
                file_owner_id = file_owner.id
            else:
                response = {"success": False, "error":result["error"]}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            stored_name = f"{file_owner_id}_{args["file_name"]}"
            file = Path(os.path.join(self.upload_path, stored_name))
            result = self.db.get_file_by_name(stored_name)
            if result["success"]:
                file_data = result["file_data"]
            else:
                response = {"success": False, "error":result["error"]}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            if not file.exists():
                response = {"success": False, "error":"File does not exist"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            else:
                nonce = self.crypto.b64encode(file_data["gcm_nonce"])
                auth_tag = self.crypto.b64encode(file_data["auth_tag"])

                response = {"success": True, "nonce": nonce, "auth_tag":auth_tag}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

            recv_signal = self.recv_json(session.conn)
            if not recv_signal and not (recv_signal["success"]):
                return
            

            encrypted_data = file.read_bytes()
            chunk_size = 64 * 1024
            if encrypted_data:
                total_chunk = len(encrypted_data) // chunk_size
                if len(encrypted_data) % chunk_size:
                    total_chunk += 1
            else:
                total_chunk = 0

            for chunk_num in range(0,total_chunk):
                start = chunk_num * chunk_size
                end = min(start + chunk_size, len(encrypted_data))
                chunk = encrypted_data[start:end]
                chunk_encoded = self.crypto.b64encode(chunk)
                chunk_payload = {"payload_type": "chunk","chunk":chunk_encoded,"chunk_num":chunk_num,"chunk_size":len(chunk),"last_chunk":False}
                if((chunk_num+1) == total_chunk):
                    chunk_payload["last_chunk"] = True
                session.conn.sendall((json.dumps(chunk_payload) + "\n").encode("utf-8"))

                recv_signal = self.recv_json(session.conn)
                if not(recv_signal) or not(recv_signal["success"]):
                    return
            
            result = self.db.get_file_permission_by_id(file_data["id"], session.user.id)
            if result["success"]:
                file_permission_data = result["file_permission"]
                file_permission = {"payload_type":"file_permission"}
                file_permission["ephemeral_public_key"] = file_permission_data["ephemeral_public_key"]
                file_permission["nonce"] = self.crypto.b64encode(file_permission_data["nonce"])
                file_permission["salt"] = self.crypto.b64encode(file_permission_data["salt"])
                file_permission["info"] = self.crypto.b64encode(file_permission_data["info"])
                file_permission["tag"] = self.crypto.b64encode(file_permission_data["key_auth_tag"])
                file_permission["encrypted_key"] = self.crypto.b64encode(file_permission_data["encrypted_file_key"])
                session.conn.sendall((json.dumps(file_permission) + "\n").encode("utf-8"))
                return
            else:
                response = {"payload_type":"error", "error":result["error"]}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
        except Exception as e:
            response = {"success": False, "payload_type":"error", "error":str(e)}
            session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
            return

        
    def upload(self,args,session:Session):
        try:
            if not session.is_authenticated:
                response = {"success":False, "error": "User not authenticated"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            
            metadata = self.recv_json(session.conn)
            if not metadata or metadata["payload_type"] != "metadata":
                response = {"success":False, "error": "Error receiving file metada"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            else:
                response = {"success":True}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

            file_name = metadata["file_name"]
            file_size = metadata["file_size"]
            nonce = self.crypto.b64decode(metadata["encryption"]["nonce"])
            auth_tag = self.crypto.b64decode(metadata["encryption"]["auth_tag"])
            mime_type = metadata["mime_type"]
            
            encrypted_data_parts = []
            last_chunk = False
            expected_chunk = 0
            while not(last_chunk):
                chunk_payload = self.recv_json(session.conn)
                if not chunk_payload or (chunk_payload["payload_type"] != "chunk") or (chunk_payload["chunk_num"] != expected_chunk):
                    response = {"success":False, "error": "Error receiving file data"}
                    session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                    return
                
                response = {"success":True}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

                chunk = self.crypto.b64decode(chunk_payload["chunk"])
                encrypted_data_parts.append(chunk)
                expected_chunk+=1
                last_chunk = chunk_payload["last_chunk"]
            encrypted_data = b''.join(encrypted_data_parts)

            file_permission = self.recv_json(session.conn)
            if not file_permission or file_permission["payload_type"] != "file_permission":
                response = {"success":False, "error":"Error receiving encrypted file key"}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            else:
                response = {"success":True}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

            
            encrypted_file_key = self.crypto.b64decode(file_permission["encrypted_key"])
            ephemeral_public_key =   file_permission["ephemeral_public_key"]
            key_wrap_nonce = self.crypto.b64decode(file_permission["nonce"])
            salt = self.crypto.b64decode(file_permission["salt"])
            info = self.crypto.b64decode(file_permission["info"])
            key_auth_tag = self.crypto.b64decode(file_permission["tag"])

            stored_filename = f"{session.user.id}_{file_name}"
            file_obj = File(file_name,stored_filename,session.user.id, session.user.username,file_size,None,auth_tag,mime_type,nonce,session.user.username)
            file_permission_obj = FilePermission(file_obj.id,session.user.id,encrypted_file_key,ephemeral_public_key,key_wrap_nonce,salt,info,key_auth_tag,file_obj.owner_id)

            output_path = os.path.join(self.upload_path, f"{file_obj.owner_id}_{file_name}")
            file = Path(output_path)
            if file.exists():
                response = {"success":False, "error": "File already exist. Use 'update <file>' to modify instead."}
                session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                return
            file.write_bytes(encrypted_data)

            self.db.add_file(file_obj)
            self.db.add_file_permission(file_permission_obj)
            response = {"success":True, "message": "file saved"}
            session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except Exception as e:
            response = {"success": False, "error":str(e)}
            session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
            return
        
    def login(self, args, session:Session):
        username = args.get("username")
        password = args.get("password")
        if not all([username, password]):
            response = {"success": False, "error": "username and password required"}
        elif(not(username.isalnum())):
            response = {"success": False, "error": "Incorrect Username or Password"}
        else:
            result = self.db.get_user_by_name(username)
            if result["success"]:
                user = result["user"]
                password_hash = user.password_hash
                if(self.crypto.check_password(password,password_hash)):
                    session.authenticate(user)
                    user.last_login = datetime.now(timezone.utc)
                    result = self.db.update_user(user.id,last_login=datetime.now(timezone.utc).isoformat())
                    response = {"success":True, "message": "User authenticated", "username":user.username}
                else:
                    response = {"success":False, "error": "Incorrect Username or Password"}
            else:
                response = {"success":False, "error": "Incorrect Username or Password"}

        session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
            
        
    
    def register(self, args, session:Session):
        username = args.get("username")
        password = args.get("password")
        public_key = args.get("public_key")

        public_key_obj = self.crypto.public_key_pem_to_obj(public_key)
        
        if not all([username, password, public_key]):
            response = {"success": False, "error": "username, password, and public_key required"}
        elif(not(username.isalnum())):
            response = {"success": False, "error": "Invalid username"}
        elif(public_key_obj is None):
            response = {"success": False, "error": "Invalid public key format"}
        else:
            password_hash = self.crypto.hash_password(password)
            user = User(username,password_hash,public_key)
            result = self.db.add_user(user)
            if result["success"]:
                response = {"success": True, "message": "User registered", "user_id": user.id}
            else:
                response = {"success": False, "error": result["error"]}
        session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
    

        
    def handle_client(self, conn, addr):
        print(f"[+] Client connected: {addr}")
        buffer = ""
        session = Session(conn,addr)
        try:
            while True:
                data = conn.recv(4096).decode('utf-8')
                if not data:
                    break
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    request = json.loads(line)
                    self.process_request(request,session)
        except Exception as e:
            print(f"[!] Client {addr} disconnected: {e}")
        finally:
            conn.close()
            print(f"[-] Connection closed: {addr}")

    def process_request(self, request, session: Session):
        action = request.get("action")

        if action == "ping":
            response = {"success": True, "message": "pong"}
            session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

        elif action == "exit":
            response = {"success": True, "message": "Goodbye"}
            session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        
        elif action == "register":
            self.register(request,session)
        
        elif action == "login":
            self.login(request,session)
        
        elif action == "get_public_key":
            self.sendPublicKey(session)
        
        elif action == "upload":
            self.upload(request,session)
        
        elif action == "fetch":
            self.fetch(request,session)
        
        elif action == "ls":
            self.listFiles(session)
        
        elif action == "share":
            self.share(request,session)

        else:
            response = {"success": False, "error": "unknown action"}
            session.conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

    def start(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.ssl_cert_file, keyfile=self.ssl_key_file)

        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"[✓] Server listening on {self.host}:{self.port}")

        while True:
            conn, addr = self.sock.accept()
            secure_conn = context.wrap_socket(conn, server_side=True)
            thread = threading.Thread(target=self.handle_client, args=(secure_conn, addr), daemon=True)
            thread.start()
            self.clients.append((secure_conn, thread))


