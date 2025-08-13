from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import jwt
import bcrypt
import uuid
import qrcode
import io
import base64
import json
import asyncio
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Database Configuration ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./qr_auth.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- JWT Configuration ---
SECRET_KEY = "your_very_secret_key"  # IMPORTANT: Use a strong, secret key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    devices = relationship("DeviceSession", back_populates="user")
    qr_sessions = relationship("QRSession", back_populates="user")

class DeviceSession(Base):
    __tablename__ = "device_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    device_id = Column(String, unique=True, index=True)
    device_name = Column(String)
    session_token = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_active = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    user = relationship("User", back_populates="devices")

class QRSession(Base):
    __tablename__ = "qr_sessions"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)
    is_expired = Column(Boolean, default=False)
    device_info = Column(String, nullable=True)
    user = relationship("User", back_populates="qr_sessions")

Base.metadata.create_all(bind=engine)

# --- Pydantic Models ---
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime
    is_active: bool
    class Config: from_attributes = True

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

class UserUpdateResponse(BaseModel):
    user: UserResponse
    access_token: str
    token_type: str = "bearer"

class DeviceSessionResponse(BaseModel):
    id: int
    device_id: str
    device_name: str
    created_at: datetime
    last_active: datetime
    is_active: bool
    class Config: from_attributes = True

class QRSessionCreate(BaseModel):
    device_info: Optional[str] = None

class QRSessionResponse(BaseModel):
    session_id: str
    qr_code_data: str
    expires_at: datetime

class QRScanRequest(BaseModel):
    session_id: str

# --- FastAPI App ---
app = FastAPI(title="QR Authentication API", version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()

# --- WebSocket Connection Manager (REFACTORED) ---
class ConnectionManager:
    def __init__(self):
        self.login_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[int, List[WebSocket]] = {}

    async def connect_login(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        self.login_connections[session_id] = websocket
        logger.info(f"🔌 Login WebSocket connected for session: {session_id}")

    def disconnect_login(self, session_id: str):
        if session_id in self.login_connections:
            del self.login_connections[session_id]
            logger.info(f"🔌 Login WebSocket disconnected for session: {session_id}")

    async def connect_user(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(websocket)
        logger.info(f"🔌 User WebSocket connected for user_id: {user_id}")

    def disconnect_user(self, websocket: WebSocket, user_id: int):
        if user_id in self.user_connections:
            self.user_connections[user_id].remove(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        logger.info(f"🔌 User WebSocket disconnected for user_id: {user_id}")

    async def send_to_login_session(self, message: str, session_id: str):
        if session_id in self.login_connections:
            websocket = self.login_connections[session_id]
            try:
                await websocket.send_text(message)
                logger.info(f"✅ Message sent to login session: {session_id}")
                return True
            except Exception as e:
                logger.error(f"❌ Error sending to login session {session_id}: {e}")
                self.disconnect_login(session_id)
        return False

    async def broadcast_to_user(self, message: str, user_id: int):
        if user_id in self.user_connections:
            disconnected_sockets = []
            for websocket in self.user_connections[user_id]:
                try:
                    await websocket.send_text(message)
                except Exception:
                    disconnected_sockets.append(websocket)
            for websocket in disconnected_sockets:
                self.disconnect_user(websocket, user_id)
            logger.info(f"✅ Broadcasted message to user: {user_id}")

manager = ConnectionManager()

# --- Dependencies & Utilities ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# --- API Endpoints ---
@app.post("/auth/register", response_model=UserResponse)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == user_data.username) | (User.email == user_data.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed_password = hash_password(user_data.password)
    db_user = User(username=user_data.username, email=user_data.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/login")
def login_user(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account is disabled")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer", "user": UserResponse.from_orm(user)}

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/qr/generate", response_model=QRSessionResponse)
def generate_qr_session(db: Session = Depends(get_db)):
    session_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    qr_session = QRSession(session_id=session_id, expires_at=expires_at)
    db.add(qr_session)
    db.commit()
    qr_data_dict = {"session_id": session_id, "expires_at": expires_at.isoformat()}
    qr_code_data = generate_qr_code(json.dumps(qr_data_dict))
    return QRSessionResponse(session_id=session_id, qr_code_data=qr_code_data, expires_at=expires_at)

@app.post("/qr/scan")
async def scan_qr_code(scan_data: QRScanRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    qr_session = db.query(QRSession).filter(QRSession.session_id == scan_data.session_id).first()
    if not qr_session or qr_session.is_used or datetime.utcnow() > qr_session.expires_at:
        raise HTTPException(status_code=404, detail="QR session is invalid or has expired")
    
    qr_session.is_used = True
    qr_session.user_id = current_user.id
    
    device_id = str(uuid.uuid4())
    session_token = create_access_token(data={"sub": current_user.username, "device_id": device_id}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    device_session = DeviceSession(user_id=current_user.id, device_id=device_id, device_name=qr_session.device_info or "Desktop/Web Client", session_token=session_token)
    db.add(device_session)
    db.commit()
    
    message = {
        "type": "login_success",
        "user": json.loads(UserResponse.from_orm(current_user).json()),
        "session_token": session_token,
        "device_id": device_id
    }
    await manager.send_to_login_session(json.dumps(message), scan_data.session_id)
    
    return {"message": "Device linked successfully", "device_id": device_id, "session_token": session_token}

@app.put("/user/profile", response_model=UserUpdateResponse)
async def update_user_profile(user_data: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user_data.username and user_data.username != current_user.username:
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        current_user.username = user_data.username
    if user_data.email and user_data.email != current_user.email:
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        current_user.email = user_data.email
    
    db.commit()
    db.refresh(current_user)
    
    new_access_token = create_access_token(data={"sub": current_user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    message = {
        "type": "profile_updated",
        "user": json.loads(UserResponse.from_orm(current_user).json()),
        "access_token": new_access_token
    }
    await manager.broadcast_to_user(json.dumps(message), current_user.id)
    
    return UserUpdateResponse(user=current_user, access_token=new_access_token)

# --- WebSocket Endpoints (REFACTORED) ---
@app.websocket("/ws/login/{session_id}")
async def websocket_login_endpoint(websocket: WebSocket, session_id: str, db: Session = Depends(get_db)):
    qr_session = db.query(QRSession).filter(QRSession.session_id == session_id).first()
    if not qr_session or qr_session.is_used or datetime.utcnow() > qr_session.expires_at:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await manager.connect_login(websocket, session_id)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect_login(session_id)

@app.websocket("/ws/listen")
async def websocket_listen_endpoint(websocket: WebSocket, token: str = Query(...), db: Session = Depends(get_db)):
    try:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        user = get_current_user(credentials, db)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect_user(websocket, user.id)
    try:
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect_user(websocket, user.id)

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Starting QR Authentication API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
