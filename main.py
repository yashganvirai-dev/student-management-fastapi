from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt

# ==========================================
# 1. DATABASE CONFIGURATION (SQLite)
# ==========================================
SQLALCHEMY_DATABASE_URL = "sqlite:///./students.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 2. DATABASE MODELS
# ==========================================
class StudentModel(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    course = Column(String, nullable=False)
    age = Column(Integer, nullable=False)

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. PYDANTIC SCHEMAS
# ==========================================
class StudentBase(BaseModel):
    name: str
    email: EmailStr
    course: str
    age: int

class StudentCreate(StudentBase):
    pass

class StudentUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    course: Optional[str] = None
    age: Optional[int] = None

class StudentResponse(StudentBase):
    id: int

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# ==========================================
# 4. AUTHENTICATION & SECURITY
# ==========================================
SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_ME_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ==========================================
# 5. FASTAPI APPLICATION & ROUTES
# ==========================================
app = FastAPI(
    title="Student Management REST API",
    description="All-in-one FastAPI project with SQLite, JWT Auth, and CRUD operations.",
    version="1.0.0"
)

# Authentication Endpoints
@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pwd = get_password_hash(user.password)
    new_user = UserModel(username=user.username, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Student Endpoints (Protected by Auth)
@app.post("/students/", response_model=StudentResponse, status_code=status.HTTP_201_CREATED)
def create_student(
    student: StudentCreate, 
    db: Session = Depends(get_db), 
    current_user: UserModel = Depends(get_current_user)
):
    db_student = StudentModel(**student.model_dump())
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return db_student

@app.get("/students/", response_model=List[StudentResponse])
def read_students(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    return db.query(StudentModel).offset(skip).limit(limit).all()

@app.get("/students/{student_id}", response_model=StudentResponse)
def read_student(
    student_id: int, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    db_student = db.query(StudentModel).filter(StudentModel.id == student_id).first()
    if db_student is None:
        raise HTTPException(status_code=404, detail="Student not found")
    return db_student

@app.put("/students/{student_id}", response_model=StudentResponse)
def update_student(
    student_id: int, 
    student: StudentUpdate, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    db_student = db.query(StudentModel).filter(StudentModel.id == student_id).first()
    if not db_student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    update_data = student.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_student, key, value)
        
    db.commit()
    db.refresh(db_student)
    return db_student

@app.delete("/students/{student_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_student(
    student_id: int, 
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    db_student = db.query(StudentModel).filter(StudentModel.id == student_id).first()
    if not db_student:
        raise HTTPException(status_code=404, detail="Student not found")
    db.delete(db_student)
    db.commit()
    return None