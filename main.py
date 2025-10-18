from fastapi import FastAPI,status,Depends
from typing_extensions import Annotated
from sqlalchemy.orm import Session
from auth.database import engine,SessionLocal
from auth.auth import router as auth_router
from auth.auth import get_current_user
from auth.models import Base


app = FastAPI()
app.include_router(auth_router)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependancy= Annotated[Session,Depends(get_current_user)]


@app.get("/", status_code=status.HTTP_200_OK)
async def user(user:user_dependancy,db: db_dependency):
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )
    return {"user": user}
