import os
import logging
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from fastapi import FastAPI, Depends, HTTPException, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.future import select
from passlib.hash import bcrypt
import asyncio
# Import models to ensure they are loaded
from models import Base, User
from schemas import UserCreate, UserResponse
from typing import List


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=True,  # Set to False in production
    future=True
)

# Create async session
SessionLocal = sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

# FastAPI app setup
app = FastAPI()
# Create a router for users
router = APIRouter()

# CORS middleware
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database session dependency
async def get_db():
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Table creation function
async def create_tables():
    async with engine.begin() as conn:
        # Import all models here to ensure they are loaded
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created successfully!")

# Signup endpoint
@app.post("/signup", response_model=UserResponse)
async def signup(user: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        logger.info(f"Received signup request for email: {user.email}")
        
        # Check if user exists
        result = await db.execute(select(User).filter(User.email == user.email))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            logger.warning(f"Signup attempt with existing email: {user.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash password
        hashed_password = bcrypt.hash(user.password)
        
        # Create new user
        new_user = User(
            username=user.username, 
            email=user.email, 
            password=hashed_password
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        logger.info(f"User created successfully: {new_user.email}")
        return new_user
    
    except Exception as e:
        logger.error(f"Error during signup: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/users", response_model=List[UserResponse])
async def get_users(db: AsyncSession = Depends(get_db)):
    try:
        # Fetch all users
        result = await db.execute(select(User))
        users = result.scalars().all()
        print(users)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")


@app.post("/login")
async def login(user_login: UserLogin, db: AsyncSession = Depends(get_db)):
    try:
        logger.info(f"Login attempt for email: {user_login.email}")
        
        # Find user by email
        result = await db.execute(select(User).filter(User.email == user_login.email))
        existing_user = result.scalar_one_or_none()
        
        if not existing_user:
            logger.warning(f"Login attempt with non-existent email: {user_login.email}")
            raise HTTPException(status_code=400, detail="Invalid email or password")
        
        # Verify password
        if not bcrypt.verify(user_login.password, existing_user.password):
            logger.warning(f"Failed login attempt for email: {user_login.email}")
            raise HTTPException(status_code=400, detail="Invalid email or password")
        
        # Create session or JWT token here
        # For this example, we'll return user details
        logger.info(f"Successful login for email: {user_login.email}")
        return {
            "id": existing_user.id,
            "username": existing_user.username,
            "email": existing_user.email
        }
    
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

        
# In your main.py, include the router
app.include_router(router)

# Initialize database when the application starts
@app.on_event("startup")
async def startup_event():
    await create_tables()


# In your main.py, include this method to add the router
def include_users_router(app: FastAPI):
    app.include_router(router, tags=["users"])

include_users_router(app)
# Optional: Manual database initialization script
if __name__ == "__main__":
    asyncio.run(create_tables())


