from datetime import datetime, timezone
from models import User

class Session:
    def __init__(self, conn, addr):
        self.conn = conn              
        self.addr = addr              
        self.user = None                           
        self.is_authenticated = False
        self.is_active = True
        self.command_history = []
        self.created_at = datetime.now(timezone.utc)
    
    def authenticate(self,user:User):
        self.user = user
        self.is_authenticated = True
    
    def logout(self):
        self.user = None
        self.is_authenticated = False
