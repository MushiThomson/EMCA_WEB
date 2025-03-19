from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# ✅ Database URL (Using SQLite, change to PostgreSQL if needed)
DATABASE_URL = "sqlite:///./emca.db"

# ✅ Create Engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# ✅ Create Session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ✅ Base Model
Base = declarative_base()

# ✅ Contact Message Model
class ContactMessage(Base):
    __tablename__ = "contact_messages"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String)
    message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)  # Store time when message is received

# ✅ Project Model
class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    image_url = Column(String)

# ✅ Admin Model
class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)

# ✅ Create Tables
Base.metadata.create_all(bind=engine)
