from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
import os
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
from pydantic import BaseModel
from models import ContactMessage, Project, Admin, SessionLocal

app = FastAPI()

# ✅ Ensure uploads folder exists
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ✅ Serve uploaded images
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


# ✅ Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Pydantic Model for Contact Form
class ContactForm(BaseModel):
    name: str
    email: str
    message: str

# ✅ Re-add the Missing Contact Form API
@app.post("/contact/")
def save_message(contact: ContactForm, db: Session = Depends(get_db)):
    contact_message = ContactMessage(
        name=contact.name, 
        email=contact.email, 
        message=contact.message,
        timestamp=datetime.utcnow()  # Save time message was received)
    )
    db.add(contact_message)
    db.commit()
    return {"message": "Message received"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ✅ Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Secure GET /contact/ (Only Admins Can View Messages)
@app.get("/contact/")
def get_messages(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, "supersecretkey", algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    messages = db.query(ContactMessage).all()

     # Convert timestamp to readable format before returning
    return [
        {
            "id": msg.id,
            "name": msg.name,
            "email": msg.email,
            "message": msg.message,
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")  # Format timestamp
        }
        for msg in messages
    ]


# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

# ✅ Secret Key for JWT
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ✅ Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ✅ Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Pydantic Models
class ContactForm(BaseModel):
    name: str
    email: str
    message: str

class ProjectSchema(BaseModel):
    title: str
    description: str
    image_url: str

class AdminCreate(BaseModel):
    username: str
    password: str

# ✅ User Authentication
def authenticate_admin(username: str, password: str, db: Session):
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or not pwd_context.verify(password, admin.password_hash):
        return None
    return admin

# ✅ Create JWT Token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ✅ Register Admin (Only Run Once)
@app.post("/register-admin/")
def register_admin(admin_data: AdminCreate, db: Session = Depends(get_db)):
    existing_admin = db.query(Admin).filter(Admin.username == admin_data.username).first()
    if existing_admin:
        raise HTTPException(status_code=400, detail="Admin already exists")

    hashed_password = pwd_context.hash(admin_data.password)
    new_admin = Admin(username=admin_data.username, password_hash=hashed_password)
    db.add(new_admin)
    db.commit()
    return {"message": "Admin created successfully"}

# ✅ Login Endpoint
@app.post("/token/")
def login_admin(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    admin = authenticate_admin(form_data.username, form_data.password, db)
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token({"sub": admin.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# ✅ Protect API Routes
def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        admin = db.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return admin
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

# ✅ Modify `POST /projects/` to support image uploads
@app.post("/projects/")
async def create_project(
    title: str = Form(...),
    description: str = Form(...),
    image: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Save uploaded image
    file_location = f"{UPLOAD_DIR}/{image.filename}"
    with open(file_location, "wb") as buffer:
        buffer.write(await image.read())

    # Store project with image URL
    image_url = f"http://127.0.0.1:8000/uploads/{image.filename}"
    new_project = Project(title=title, description=description, image_url=image_url)

    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    
    return new_project

@app.get("/projects/")
def get_projects(db: Session = Depends(get_db)):
    return db.query(Project).all()

@app.get("/projects/{project_id}")
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.put("/projects/{project_id}", dependencies=[Depends(get_current_admin)])
def update_project(project_id: int, project: ProjectSchema, db: Session = Depends(get_db)):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="Project not found")

    db_project.title = project.title
    db_project.description = project.description
    db_project.image_url = project.image_url
    db.commit()
    db.refresh(db_project)
    return db_project

@app.delete("/projects/{project_id}", dependencies=[Depends(get_current_admin)])
def delete_project(project_id: int, db: Session = Depends(get_db)):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="Project not found")

    db.delete(db_project)
    db.commit()
    return {"message": "Project deleted successfully"}
