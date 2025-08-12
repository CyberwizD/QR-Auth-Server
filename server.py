from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import jwt
import bcrypt
import uuid
import qrcode
import io
import base64
from PIL import Image
import json
import asyncio
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration
SQLALCHEMY_DATABASE_URL = "sqlite:///./qr_auth.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Configuration
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationship
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
    
    # Relationship
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
    
    # Relationship
    user = relationship("User", back_populates="qr_sessions")

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models
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

class UserUpdateResponse(BaseModel):
    user: UserResponse

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

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

# FastAPI App
app = FastAPI(title="QR Authentication API", version="1.0.0")

# CORS Configuration - More explicit and permissive
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],  # All methods
    allow_headers=["*"],  # All headers
    expose_headers=["*"],  # Expose all headers
)

# Security
security = HTTPBearer()

# WebSocket Connection Manager - FIXED VERSION
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
        logger.info(f"🔌 WebSocket connected for user: {user_id}")

    def disconnect(self, websocket: WebSocket, user_id: int):
        if user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        logger.info(f"🔌 WebSocket disconnected for user: {user_id}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"❌ Error sending message: {e}")

    async def broadcast_to_user(self, message: str, user_id: int):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await self.send_personal_message(message, connection)

manager = ConnectionManager()

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        logger.info(f"🔍 Verifying token (first 20 chars): {token[:20]}...")
        logger.info(f"🔍 Token length: {len(token)}")
        logger.info(f"🔍 Token parts count: {len(token.split('.'))}")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.info(f"✅ JWT decoded successfully: {payload}")
        
        username: str = payload.get("sub")
        if username is None:
            logger.error("❌ No 'sub' field in JWT payload")
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        logger.info(f"✅ JWT verification successful for user: {username}")
        return username
    except jwt.ExpiredSignatureError as e:
        logger.error(f"❌ JWT expired: {e}")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidSignatureError as e:
        logger.error(f"❌ JWT signature invalid: {e}")
        raise HTTPException(status_code=401, detail="Invalid token signature")
    except jwt.DecodeError as e:
        logger.error(f"❌ JWT decode error: {e}")
        raise HTTPException(status_code=401, detail="Token decode error")
    except jwt.PyJWTError as e:
        logger.error(f"❌ JWT Error: {e}")
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_current_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def generate_qr_code(data: str) -> str:
    """Generate QR code and return as base64 string"""
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        raise HTTPException(status_code=500, detail="Error generating QR code")

# Background task for WebSocket notifications
async def send_websocket_notification(user_id: int, message: dict):
    """Send WebSocket notification to a user in the background"""
    try:
        logger.info(f"📨 Preparing WebSocket notification for user: {user_id}")
        logger.info(f"📨 Message: {message}")
        
        message_json = json.dumps(message)
        await manager.broadcast_to_user(message_json, user_id)
        
        logger.info(f"✅ WebSocket notification sent successfully to user: {user_id}")
        return True
    except Exception as e:
        logger.error(f"❌ Error in WebSocket notification: {e}")
        return False

# API Endpoints with better error handling

@app.post("/auth/register", response_model=UserResponse)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        # Check if user exists
        existing_user = db.query(User).filter(
            (User.username == user_data.username) | (User.email == user_data.email)
        ).first()
        
        if existing_user:
            raise HTTPException(status_code=400, detail="Username or email already registered")
        
        # Create new user
        hashed_password = hash_password(user_data.password)
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"User registered: {user_data.username}")
        return db_user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error during registration")

@app.post("/auth/login")
def login_user(user_data: UserLogin, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == user_data.username).first()
        
        if not user or not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        
        if not user.is_active:
            raise HTTPException(status_code=401, detail="User account is disabled")
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        logger.info(f"User logged in: {user_data.username}")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": UserResponse.from_orm(user)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during login")

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/qr/generate", response_model=QRSessionResponse)
def generate_qr_session(
    qr_data: QRSessionCreate,
    db: Session = Depends(get_db)
):
    try:
        # Generate unique session ID
        session_id = str(uuid.uuid4())
        
        # Set expiration (5 minutes from now)
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        
        # Create QR session
        qr_session = QRSession(
            session_id=session_id,
            expires_at=expires_at,
            device_info=qr_data.device_info
        )
        
        db.add(qr_session)
        db.commit()
        
        # Generate QR code data (JSON string)
        qr_data_dict = {
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
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
        db.rollback()
        raise HTTPException(status_code=500, detail="Error generating QR session")

@app.post("/qr/scan")
async def scan_qr_code(  # Made this async to properly handle WebSocket notifications
    scan_data: QRScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        logger.info(f"🎯 QR scan attempt by user {current_user.username} for session {scan_data.session_id}")
        
        # Find QR session
        qr_session = db.query(QRSession).filter(
            QRSession.session_id == scan_data.session_id
        ).first()
        
        if not qr_session:
            logger.warning(f"❌ QR session not found: {scan_data.session_id}")
            raise HTTPException(status_code=404, detail="QR session not found")
        
        # Check if session is expired
        if datetime.utcnow() > qr_session.expires_at:
            qr_session.is_expired = True
            db.commit()
            logger.warning(f"❌ QR session expired: {scan_data.session_id}")
            raise HTTPException(status_code=400, detail="QR code has expired")
        
        # Check if already used
        if qr_session.is_used:
            logger.warning(f"❌ QR session already used: {scan_data.session_id}")
            raise HTTPException(status_code=400, detail="QR code has already been used")
        
        # Mark session as used and associate with user
        qr_session.is_used = True
        qr_session.user_id = current_user.id
        db.commit()
        
        # Create device session
        device_id = str(uuid.uuid4())
        session_token = create_access_token(
            data={"sub": current_user.username, "device_id": device_id}
        )
        
        device_session = DeviceSession(
            user_id=current_user.id,
            device_id=device_id,
            device_name=qr_session.device_info or "Mobile Device",
            session_token=session_token
        )
        
        db.add(device_session)
        db.commit()
        
        # Send notification to desktop via WebSocket - FIXED VERSION
        try:
            message = {
                "type": "login_success",
                "user": {
                    "id": current_user.id,
                    "username": current_user.username,
                    "email": current_user.email
                },
                "session_token": session_token,
                "device_id": device_id
            }
            
            # Use await to properly send the WebSocket message
            notification_success = await send_websocket_notification(scan_data.session_id, message)
            
            if notification_success:
                logger.info(f"✅ WebSocket notification sent successfully")
            else:
                logger.warning(f"⚠️ WebSocket notification failed, but device was still linked")
                
        except Exception as ws_error:
            logger.error(f"❌ WebSocket notification error: {ws_error}")
            # Don't fail the request if WebSocket fails
        
        logger.info(f"✅ Device linked successfully: {device_id} for user {current_user.username}")
        return {
            "message": "Device linked successfully",
            "device_id": device_id,
            "session_token": session_token
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning QR code: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error during QR scan")

@app.get("/devices", response_model=List[DeviceSessionResponse])
def get_user_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        devices = db.query(DeviceSession).filter(
            DeviceSession.user_id == current_user.id,
            DeviceSession.is_active == True
        ).all()
        
        return devices
    except Exception as e:
        logger.error(f"Error getting user devices: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving devices")

@app.delete("/devices/{device_id}")
def revoke_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        device = db.query(DeviceSession).filter(
            DeviceSession.device_id == device_id,
            DeviceSession.user_id == current_user.id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        device.is_active = False
        db.commit()
        
        logger.info(f"Device revoked: {device_id}")
        return {"message": "Device revoked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revoking device: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Error revoking device")

class UserUpdateResponse(BaseModel):
    user: UserResponse
    access_token: str
    token_type: str

@app.put("/user/profile", response_model=UserUpdateResponse)
async def update_user_profile(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        if user_data.username:
            # Check if username is already taken
            existing_user = db.query(User).filter(User.username == user_data.username).first()
            if existing_user and existing_user.id != current_user.id:
                raise HTTPException(status_code=400, detail="Username already registered")
            current_user.username = user_data.username

        if user_data.email:
            # Check if email is already taken
            existing_user = db.query(User).filter(User.email == user_data.email).first()
            if existing_user and existing_user.id != current_user.id:
                raise HTTPException(status_code=400, detail="Email already registered")
            current_user.email = user_data.email

        db.commit()
        db.refresh(current_user)
        
        # Generate a new token with the updated user info
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": current_user.username}, expires_delta=access_token_expires
        )
        
        # Notify all active devices of the user about the profile update
        message = {
            "type": "profile_updated",
            "user": UserResponse.from_orm(current_user).dict(),
            "access_token": new_access_token
        }
        await send_websocket_notification(current_user.id, message)

        logger.info(f"User profile updated for: {current_user.username}")
        return {
            "user": current_user,
            "access_token": new_access_token,
            "token_type": "bearer"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error during profile update")

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# WebSocket Endpoint - IMPROVED VERSION
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    try:
        username = verify_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
        user = db.query(User).filter(User.username == username).first()
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await manager.connect(websocket, user.id)
        
        try:
            while True:
                data = await websocket.receive_text()
                logger.info(f"📨 WebSocket received from user {user.id}: {data}")
                # Echo back for keep-alive
                await websocket.send_text(f"Echo: {data}")
        except WebSocketDisconnect:
            manager.disconnect(websocket, user.id)
    except Exception as e:
        logger.error(f"❌ WebSocket endpoint error: {e}")

@app.get("/")
def root():
    return {
        "message": "QR Authentication API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "register": "/auth/register",
            "login": "/auth/login",
            "me": "/auth/me",
            "generate_qr": "/qr/generate",
            "scan_qr": "/qr/scan",
            "devices": "/devices",
            "websocket": "/ws/{session_id}",
            "health": "/health"
        }
    }

if __name__ == "__main__":
    import uvicorn
    logger.info("� Starting QR Authentication API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
