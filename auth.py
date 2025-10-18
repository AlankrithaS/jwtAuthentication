from datetime import datetime, timedelta
from typing_extensions import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from auth.database import SessionLocal
from auth.models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt


router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

SECRET_KEY = "4899b914df58156a5d1766d2166acfef07111030f6be1b61314119c22b640553"
ALGORITHM = "HS256"

bycryt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

class CreateUserRequest(BaseModel) :
    username:str
    password:str   
    
class Token (BaseModel):
    access_token:str
    token_type:str
    
class TokenWithRefresh(Token):
    refresh_token: str
    
class RefreshTokenRequest(BaseModel):
    refresh_token: str



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency= Annotated[Session,Depends(get_db)]

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_request = User(
        username=create_user_request.username,
        hashed_password=bycryt_context.hash(create_user_request.password)
    )

    db.add(create_user_request)
    db.commit()


@router.post("/token", response_model=TokenWithRefresh)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate user"
        )
    
    access_token = create_access_token(user.username, user.id, timedelta(minutes=60))
    refresh_token = create_refresh_token(user.username, user.id, timedelta(days=7))

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}


def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not bycryt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {"sub": username, "id": user_id}
    expire = datetime.now() + expires_delta
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {"sub": username, "id": user_id}
    expire = datetime.now() + expires_delta
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)



async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate user"
            )
        return {"username": username, "id": user_id}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate user"
        )


@router.post("/refresh", response_model=Token)
async def refresh_access_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
        new_access_token = create_access_token(username, user_id, timedelta(minutes=60))
        return {"access_token": new_access_token, "token_type": "bearer"}
    
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")