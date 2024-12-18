from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

# Important: Use declarative_base from sqlalchemy.orm for newer SQLAlchemy versions
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)