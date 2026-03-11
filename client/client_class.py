import mimetypes
import socket
import json
from crypto_class import CryptoClass
import pwinput
import os
import ssl
from pathlib import Path
from tabulate import tabulate
import shlex
from datetime import datetime

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.crypto = CryptoClass()

    def connect(self):
        # Create TCP socket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create TLS context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Load trusted server certificate
        cert_path = os.path.join(os.getcwd(),"server.crt")
        context.load_verify_locations(cert_path)

        # Wrap socket with TLS
        self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)

        # Connect securely
        self.sock.connect((self.host, self.port))

        print("[✓] TLS connection established")
        self.terminal()

    def recv_json(self):
        sock = self.sock
        buffer = ""
        while True:
            data = sock.recv(4096).decode("utf-8")
            if not data:  # connection closed
                return None
            buffer += data
            if "\n" in buffer:  # full message received
                line, buffer = buffer.split("\n", 1)
                return json.loads(line)
    
    @staticmethod
    def format_file_size(size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/(1024**2):.1f} MB"
        else:
            return f"{size_bytes/(1024**3):.2f} GB"
    
    @staticmethod
    def format_datetime(iso_string, format="%Y-%m-%d %H:%M:%S"):
        if not iso_string:
            return "N/A"
        
        dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        
        return dt.strftime(format)
            
    def listFiles(self, request):
        try:
            self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            response = self.recv_json()
            if response["success"]:
                files = response["files_data"]
            else:
                print(response["error"])
                return
            headers = ["Filename", "Owner", "Size", "Modified At", "Modified By"]
            table_data = []
            for file in files:
                filename = file["filename"]
                owner = file["owner"]
                file_size = self.format_file_size(file["file_size"])
                modified_at = self.format_datetime(file["modified_at"])
                modified_by = file["last_modified_by"]
                table_data.append([filename,owner,file_size,modified_at,modified_by])
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            print(f"\nTotal: {len(files)} files")
        except Exception as e:
            print(str(e))
            
    def share(self,request,args):
        try:
            if len(args) != 3:
                print("usage: share '<file_name>' '<private_key_pem_file>' <username>")
                return None
            file_name = args[0]
            private_key_pem_file = Path(args[1])
            username = args[2]
            
            if not(private_key_pem_file.exists()):
                print(f"{args[1]} does not exist")
                return None

            if not(username.isalnum()):
                print("Invalid Username")
                return None
            
            private_key_pem = private_key_pem_file.read_text()
            private_key = self.crypto.private_key_pem_to_obj(private_key_pem)

            request["file_name"] = file_name
            request["username"] = username
            self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))

            file_permission = self.recv_json()
            if file_permission["success"]:
                encrypted_file_key = self.crypto.b64decode(file_permission["encrypted_key"])
                ephemeral_public_key =  file_permission["ephemeral_public_key"]
                key_wrap_nonce = self.crypto.b64decode(file_permission["nonce"])
                salt = self.crypto.b64decode(file_permission["salt"])
                info = self.crypto.b64decode(file_permission["info"])
                key_auth_tag = self.crypto.b64decode(file_permission["tag"])

                user_public_key_pem = file_permission["user_public_key"]
                file_key = self.crypto.ecies_decrypt_key(private_key,encrypted_file_key,ephemeral_public_key,key_wrap_nonce,salt,info,key_auth_tag)
                if not(file_key):
                    print("Error granting permission")
                    return None
                user_public_key = self.crypto.public_key_pem_to_obj(user_public_key_pem)
                wrapped_key_data = self.crypto.ecies_encrypt_key(user_public_key, file_key)
                new_permission = {"success": True}
                new_permission["ephemeral_public_key"] = wrapped_key_data["ephemeral_public_key"]
                new_permission["nonce"] = self.crypto.b64encode(wrapped_key_data["nonce"])
                new_permission["salt"] = self.crypto.b64encode(wrapped_key_data["salt"])
                new_permission["info"] = self.crypto.b64encode(wrapped_key_data["info"])
                new_permission["tag"] = self.crypto.b64encode(wrapped_key_data["tag"])
                new_permission["encrypted_key"] = self.crypto.b64encode(wrapped_key_data["encrypted_key"])
                self.sock.sendall((json.dumps(new_permission) + "\n").encode("utf-8"))

                response = self.recv_json()
                if response["success"]:
                    print(f"File shared to {username}")
                else:
                    print(response["error"])
                return
            else:
                print(file_permission["error"])
                return
        except Exception as e:
            print(str(e))
            


    def fetch(self,request,args):
        try:
            if len(args) != 4:
                print("usage: fetch '<file_name>' '<private_key_pem_file>' <file_owner> '<output_file>'")
                return None

            file_name = args[0]
            private_key_pem_file = Path(args[1])
            file_owner = args[2]
            output = Path(args[3])

            if not(private_key_pem_file.exists()):
                print(f"{args[1]} does not exist")
                return None
            
            if not(file_owner.isalnum()):
                print("Invalid file owner name")
                return None
            
            request["file_owner"] = file_owner
            request["file_name"] = file_name
            self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            response_1 = self.recv_json()
            if not(response_1) or not(response_1["success"]):
                print(response_1["error"])
                return None
            
            nonce = self.crypto.b64decode(response_1["nonce"])
            auth_tag = self.crypto.b64decode(response_1["auth_tag"])
            
            encrypted_data_parts = []
            last_chunk = False
            expected_chunk = 0
            start_recv = {"success": True}
            self.sock.sendall((json.dumps(start_recv) + "\n").encode("utf-8"))
            while not(last_chunk):
                chunk_payload = self.recv_json()
                if not chunk_payload or (chunk_payload["payload_type"] != "chunk") or (chunk_payload["chunk_num"] != expected_chunk):
                    print("Error receiving file data")
                    return None
                
                self.sock.sendall((json.dumps(start_recv) + "\n").encode("utf-8"))
                
                chunk = self.crypto.b64decode(chunk_payload["chunk"])
                encrypted_data_parts.append(chunk)
                expected_chunk+=1
                last_chunk = chunk_payload["last_chunk"]
            encrypted_data = b''.join(encrypted_data_parts)

            file_permission = self.recv_json()
            if not file_permission or file_permission["payload_type"] != "file_permission":
                print(file_permission["error"])
                return None
            encrypted_file_key = self.crypto.b64decode(file_permission["encrypted_key"])
            ephemeral_public_key =  file_permission["ephemeral_public_key"]
            key_wrap_nonce = self.crypto.b64decode(file_permission["nonce"])
            salt = self.crypto.b64decode(file_permission["salt"])
            info = self.crypto.b64decode(file_permission["info"])
            key_auth_tag = self.crypto.b64decode(file_permission["tag"])            

            private_key_pem = private_key_pem_file.read_text()
            private_key = self.crypto.private_key_pem_to_obj(private_key_pem)
            file_key = self.crypto.ecies_decrypt_key(private_key,encrypted_file_key,ephemeral_public_key,key_wrap_nonce,salt,info,key_auth_tag)
            if not(file_key):
                print("Error decrypting file")
                return None
            
            decryption_result = self.crypto.aes_gcm_decrypt_data(encrypted_data,file_key,nonce,auth_tag)
            if decryption_result["success"]:
                decrypted_data = decryption_result["decrypted_data"]
                output.write_bytes(decrypted_data)
                print(f"{file_name} by {file_owner} fetched to {output}")
            else:
                print(decryption_result["error"])
                return None
            
        except Exception as e:
            print(str(e))
            return None
            
            
    
    def upload(self, request,args):
        try:
            if len(args) != 1:
                print("usage: upload '<file_name>'")
                return None
            
            file = Path(args[0])
            
            public_key_json = self.getPublicKey()
            if(public_key_json["success"]):
                public_key_pem = public_key_json["public_key"]
            else:
                print(public_key_json["error"])
                return
            public_key = self.crypto.public_key_pem_to_obj(public_key_pem)

            file_data = file.read_bytes()
            encryption_result = self.crypto.aes_gcm_encrypt_data(file_data)

            if encryption_result["success"]:
                encrypted_data = encryption_result["encrypted_data"]
                file_key = encryption_result["key"]
                nonce = encryption_result["nonce"]
                auth_tag = encryption_result["auth_tag"]
            else:
                print(encryption_result["error"])
                return
            mime_type, encoding = mimetypes.guess_type(str(file))

            metadata = {"payload_type": "metadata"}
            metadata["file_name"] = file.name
            metadata["file_size"] = file.stat().st_size
            metadata["encryption"] = {"nonce":self.crypto.b64encode(nonce), "auth_tag":self.crypto.b64encode(auth_tag)}
            metadata["mime_type"] = mime_type
            self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            self.sock.sendall((json.dumps(metadata) + "\n").encode("utf-8"))
            response_1 = self.recv_json()
            if not(response_1) or not(response_1["success"]):
                print(response_1["error"])
                return

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
                self.sock.sendall((json.dumps(chunk_payload) + "\n").encode("utf-8"))
                response_2 = self.recv_json()
                if not(response_2) or not(response_2["success"]):
                    print(response_2["error"])
                    return
            
            file_permission = {"payload_type":"file_permission"}
            wrapped_key_data = self.crypto.ecies_encrypt_key(public_key, file_key)
            file_permission["ephemeral_public_key"] = wrapped_key_data["ephemeral_public_key"]
            file_permission["nonce"] = self.crypto.b64encode(wrapped_key_data["nonce"])
            file_permission["salt"] = self.crypto.b64encode(wrapped_key_data["salt"])
            file_permission["info"] = self.crypto.b64encode(wrapped_key_data["info"])
            file_permission["tag"] = self.crypto.b64encode(wrapped_key_data["tag"])
            file_permission["encrypted_key"] = self.crypto.b64encode(wrapped_key_data["encrypted_key"])
            self.sock.sendall((json.dumps(file_permission) + "\n").encode("utf-8"))
            response_3 = self.recv_json()
            if not(response_3) or not(response_3["success"]):
                print(response_3["error"])
                return
            
            
            response_4 = self.recv_json()
            if not(response_4) or not(response_4["success"]):
                print(response_4["error"])
                return
            elif(response_4["success"] and response_4["message"] == "file saved"):
                print(f"{file.name} uploaded successfully")
            else:
                print("Server error")

        except Exception as e:
            print(str(e))



    def getPublicKey(self):
        request = {"action":"get_public_key"}
        self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = self.recv_json()
        return response

    
    def login(self,request):
        uname = str(input("Username: "))
        if(not(uname.isalnum())):
            print("Invalid username")
            return ""
        password = pwinput.pwinput()
        request["username"] = uname
        request["password"] = password
        self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = self.recv_json()
        if(response["success"]):
            print(response["message"])
            return response["username"]
        else:
            print(response["error"])
            return ""
        
    def register(self,request):
        uname = str(input("Username: "))
        if(not(uname.isalnum())):
            print("Invalid username")
            return False

        password = pwinput.pwinput()
        confirm_password = pwinput.pwinput(prompt="Confirm Password: ")
        if(password != confirm_password):
            print("Password doesn't match!")
            return False
        public_key_file = str(input("Full path to public-key (.pem): "))

        try:
            with open(public_key_file, "r") as key_file:
                public_key_pem = key_file.read()
        except:
            print("Invalid public key file")
            return False
        
        request["username"] = uname
        request["password"] = password
        request["public_key"] = public_key_pem
        self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = self.recv_json()
        if(response["success"]):
            print(response["message"])
        else:
            print(response["error"])
    
    
        
    def terminal(self):
        terminal_user = ""

        while True:
            command = input(f"{terminal_user}> ")
            command = shlex.split(command)
            action = command[0]
            args = command[1:] if len(command) > 1 else []
            request = {"action": action}

            if action == "ping":
                self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
                response = self.sock.recv(4096).decode("utf-8")
                print(response)

            elif action == "exit":
                self.sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
                response = self.recv_json()
                print(response["message"])
                break
            
            elif action == "register":
                self.register(request)
            
            elif action == "login":
                terminal_user = self.login(request)
            
            elif action == "upload":
                self.upload(request,args)
            
            elif action == "fetch":
                self.fetch(request,args)
            
            elif action == "ls":
                self.listFiles(request)
            
            elif action == "share":
                self.share(request,args)
            
            else:
                continue


