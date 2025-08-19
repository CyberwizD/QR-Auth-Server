# Add these imports at the top
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
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
SECRET_KEY = "your_very_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_active = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)
    user = relationship("User", back_populates="devices")

class QRSession(Base):
    __tablename__ = "qr_sessions"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
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
    class Config: 
        from_attributes = True

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
    class Config: 
        from_attributes = True

class QRSessionCreate(BaseModel):
    device_info: Optional[str] = None

class QRSessionResponse(BaseModel):
    session_id: str
    qr_code_data: str
    expires_at: datetime

class QRScanRequest(BaseModel):
    session_id: str

# --- FastAPI App ---
app = FastAPI(title="QR Authentication API", version="1.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer()

# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.login_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[int, List[WebSocket]] = {}
        self.general_connections: Dict[str, WebSocket] = {}  # For general user connections

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
        
        # Send connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "WebSocket connection established"
        }))

    def disconnect_user(self, websocket: WebSocket, user_id: int):
        if user_id in self.user_connections and websocket in self.user_connections[user_id]:
            self.user_connections[user_id].remove(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        logger.info(f"🔌 User WebSocket disconnected for user_id: {user_id}")

    async def connect_general(self, websocket: WebSocket, connection_id: str, user_id: int):
        await websocket.accept()
        self.general_connections[connection_id] = websocket
        logger.info(f"🔌 General WebSocket connected: {connection_id} for user: {user_id}")
        
        # Send connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "WebSocket connection established",
            "user_id": user_id
        }))

    def disconnect_general(self, connection_id: str):
        if connection_id in self.general_connections:
            del self.general_connections[connection_id]
            logger.info(f"🔌 General WebSocket disconnected: {connection_id}")

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
        # Send to user-specific connections
        if user_id in self.user_connections:
            disconnected_sockets = []
            for websocket in self.user_connections[user_id]:
                try:
                    await websocket.send_text(message)
                except Exception:
                    disconnected_sockets.append(websocket)
            
            for ws in disconnected_sockets:
                self.disconnect_user(ws, user_id)
        
        # Also send to general connections (for backward compatibility)
        disconnected_connections = []
        for conn_id, websocket in self.general_connections.items():
            try:
                await websocket.send_text(message)
            except Exception:
                disconnected_connections.append(conn_id)
        
        for conn_id in disconnected_connections:
            self.disconnect_general(conn_id)
            
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
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token: no subject")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user_from_token(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
        user = db.query(User).filter(User.username == username).first()
        return user
    except:
        return None

def generate_qr_code(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return base64.b64encode(buffer.getvalue()).decode()

# --- API Endpoints ---
@app.get("/")
def root():
    return {"message": "QR Authentication API is running", "version": "1.2.0"}

@app.post("/qr/generate", response_model=QRSessionResponse)
def generate_qr_session(qr_data: Optional[QRSessionCreate] = None, db: Session = Depends(get_db)):
    """Generate a new QR session for device authentication"""
    try:
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        
        # Handle optional QRSessionCreate data
        device_info = None
        if qr_data and qr_data.device_info:
            device_info = qr_data.device_info
        
        qr_session = QRSession(
            session_id=session_id, 
            expires_at=expires_at, 
            device_info=device_info
        )
        
        db.add(qr_session)
        db.commit()
        
        # Create QR code data
        qr_data_dict = {
            "session_id": session_id, 
            "expires_at": expires_at.isoformat()
        }
        qr_code_data = generate_qr_code(json.dumps(qr_data_dict))
        
        logger.info(f"QR session generated: {session_id}")
        
        return QRSessionResponse(
            session_id=session_id, 
            qr_code_data=qr_code_data, 
            expires_at=expires_at
        )
    except Exception as e:
        logger.error(f"Error generating QR session: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate QR session: {str(e)}")

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
    return {"access_token": access_token, "token_type": "bearer", "user": UserResponse.model_validate(user)}

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/devices", response_model=List[DeviceSessionResponse])
def get_user_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    devices = db.query(DeviceSession).filter(
        DeviceSession.user_id == current_user.id,
        DeviceSession.is_active == True
    ).all()
    return devices

@app.delete("/devices/{device_id}")
def revoke_device(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    device = db.query(DeviceSession).filter(
        DeviceSession.device_id == device_id,
        DeviceSession.user_id == current_user.id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    db.delete(device)
    db.commit()
    return {"message": "Device revoked successfully"}

@app.post("/qr/scan")
async def scan_qr_code(scan_data: QRScanRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    qr_session = db.query(QRSession).filter(QRSession.session_id == scan_data.session_id).first()

    # Validate the QR session
    if not qr_session or qr_session.is_used:
        raise HTTPException(status_code=404, detail="QR session is invalid or already used")

    # Ensure expires_at is timezone-aware (UTC)
    expires_at_utc = qr_session.expires_at
    if expires_at_utc.tzinfo is None:
        expires_at_utc = expires_at_utc.replace(tzinfo=timezone.utc)

    # Check if the session has expired
    if datetime.now(timezone.utc) > expires_at_utc:
        raise HTTPException(status_code=404, detail="QR session has expired")
    
    qr_session.is_used = True
    qr_session.user_id = current_user.id
    
    device_id = str(uuid.uuid4())
    session_token = create_access_token(
        data={"sub": current_user.username, "device_id": device_id}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    device_session = DeviceSession(
        user_id=current_user.id, 
        device_id=device_id, 
        device_name=qr_session.device_info or "Desktop/Web Client", 
        session_token=session_token
    )
    db.add(device_session)
    db.commit()
    
    message = {
        "type": "login_success",
        "user": json.loads(UserResponse.model_validate(current_user).model_dump_json()),
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
    
    new_access_token = create_access_token(
        data={"sub": current_user.username}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    message = {
        "type": "profile_updated",
        "user": json.loads(UserResponse.model_validate(current_user).model_dump_json()),
        "access_token": new_access_token
    }
    await manager.broadcast_to_user(json.dumps(message), current_user.id)
    
    return UserUpdateResponse(user=current_user, access_token=new_access_token)

# --- WebSocket Endpoints ---
@app.websocket("/ws/login/{session_id}")
async def websocket_login_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for QR login sessions"""
    try:
        # Get database session
        db = SessionLocal()
        try:
            qr_session = db.query(QRSession).filter(QRSession.session_id == session_id).first()
            
            # Validate QR session exists and is not expired
            if not qr_session:
                logger.error(f"QR session not found: {session_id}")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session not found")
                return
                
            if qr_session.is_used:
                logger.error(f"QR session already used: {session_id}")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session already used")
                return
                
            # Compare timezone-aware datetimes
            current_time = datetime.now(timezone.utc)
            if qr_session.expires_at.tzinfo is None:
                # If expires_at is naive, make it UTC
                expires_at_utc = qr_session.expires_at.replace(tzinfo=timezone.utc)
            else:
                expires_at_utc = qr_session.expires_at
                
            if current_time > expires_at_utc:
                logger.error(f"QR session expired: {session_id}")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session expired")
                return
                
        finally:
            db.close()
        
        # Connect to manager
        await manager.connect_login(websocket, session_id)
        
        try:
            while True:
                # Send periodic ping to keep connection alive
                try:
                    ping_message = json.dumps({
                        "type": "ping", 
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "session_id": session_id
                    })
                    await websocket.send_text(ping_message)
                    await asyncio.sleep(30)  # Ping every 30 seconds
                except Exception as e:
                    logger.error(f"Error sending ping to {session_id}: {e}")
                    break
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for session: {session_id}")
        except Exception as e:
            logger.error(f"WebSocket error for session {session_id}: {e}")
        finally:
            manager.disconnect_login(session_id)
            
    except Exception as e:
        logger.error(f"Critical error in WebSocket login endpoint: {e}")
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Internal server error")
        except:
            pass

@app.websocket("/ws/listen")
async def websocket_listen_endpoint(websocket: WebSocket, token: str = Query(...)):
    """WebSocket endpoint for authenticated user connections"""
    try:
        # Validate token and get user
        db = SessionLocal()
        try:
            user = get_current_user_from_token(token, db)
            if not user:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
                return
        finally:
            db.close()

        await manager.connect_user(websocket, user.id)
        
        try:
            while True:
                # Send periodic ping to keep connection alive
                try:
                    ping_message = json.dumps({
                        "type": "ping", 
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "user_id": user.id
                    })
                    await websocket.send_text(ping_message)
                    await asyncio.sleep(30)  # Ping every 30 seconds
                except Exception as e:
                    logger.error(f"Error sending ping to user {user.id}: {e}")
                    break
        except WebSocketDisconnect:
            logger.info(f"User WebSocket disconnected: {user.id}")
        finally:
            manager.disconnect_user(websocket, user.id)
            
    except Exception as e:
        logger.error(f"Critical error in WebSocket listen endpoint: {e}")
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Internal server error")
        except:
            pass

# General WebSocket endpoint for backward compatibility
@app.websocket("/ws")
async def websocket_general_endpoint(websocket: WebSocket, token: str = Query(...)):
    """General WebSocket endpoint for backward compatibility"""
    try:
        # Validate token and get user
        db = SessionLocal()
        try:
            user = get_current_user_from_token(token, db)
            if not user:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
                return
        finally:
            db.close()

        connection_id = str(uuid.uuid4())
        await manager.connect_general(websocket, connection_id, user.id)
        
        try:
            while True:
                # Keep connection alive and handle any incoming messages
                try:
                    # Wait for messages or send periodic pings
                    message = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                    # Echo back for debugging
                    echo_response = json.dumps({
                        "type": "echo",
                        "original_message": message,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    await websocket.send_text(echo_response)
                except asyncio.TimeoutError:
                    # Send ping if no message received in 30 seconds
                    ping_message = json.dumps({
                        "type": "ping", 
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "connection_id": connection_id
                    })
                    await websocket.send_text(ping_message)
                except Exception as e:
                    logger.error(f"Error in WebSocket communication: {e}")
                    break
        except WebSocketDisconnect:
            logger.info(f"General WebSocket disconnected: {connection_id}")
        finally:
            manager.disconnect_general(connection_id)
            
    except Exception as e:
        logger.error(f"Critical error in general WebSocket endpoint: {e}")
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Internal server error")
        except:
            pass

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Starting QR Authentication API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
