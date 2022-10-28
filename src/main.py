from datetime import datetime, timedelta
import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# openssl rand -hex 32
SECRET_KEY = "f0ee8087d6bdddec649d2aa88887ddaf36ad6c0d7fe45fb92f5a9a7bbd1ab362"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "refresh_token": "refresh_token",
        "disabled": False,
    },
    "pontus": {
        "username": "pontus",
        "full_name": "Pontus Backman",
        "email": "pontus.backman@spinit.se",
        "hashed_password": "$2b$12$BdJrh8p9TJLwxsOH2XPAOu/WtKgIsyKkLQZ86id/8yKDd5V3.D2lm",
        "refresh_token": "fresh",
        "disabled": False,
    },
}


class Token(BaseModel):
    token: str
    refreshToken: str


class TokenData(BaseModel):
    username: str


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str
    refresh_token: str


class UserDetails(BaseModel):
    id: int
    imagePath: str
    isSeller: bool
    name: str
    profilePictureName: str
    username: str
    features: list[str]


class Country(BaseModel):
    id: int
    nameInSwedish: str
    nameInEnglish: str


class LoginBody(BaseModel):
    username: str
    password: str
    grant_type: str = "password"


class RefreshBody(BaseModel):
    RefreshToken: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token/v2")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/api/token/v2", response_model=Token)
async def login_for_access_token(body: LoginBody) -> Token:
    user = authenticate_user(
        fake_users_db, body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return Token(token=access_token, refreshToken=user.refresh_token)


@app.post("/api/token/v2/refresh")
async def refresh_token(body: RefreshBody) -> Token:
    for user in fake_users_db.values():
        if user["refresh_token"] == body.RefreshToken:
            access_token_expires = timedelta(
                minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user["username"]}, expires_delta=access_token_expires
            )
            user["refresh_token"] = secrets.token_urlsafe(32)
            return Token(token=access_token, refreshToken=user["refresh_token"])

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid refresh token",
    )


@app.get("/api/me/details", response_model=UserDetails)
async def get_me_details(current_user: User = Depends(get_current_active_user)) -> UserDetails:
    return UserDetails(
        id=1,
        imagePath="",
        isSeller=True,
        name="Pontus Backman",
        profilePictureName="",
        username=current_user.username,
        features=["view users", "view greenfee", "view customer", "view economy",
                  "view leaderboard", "view offers", "packaging", "view roles", "view search"],
    )


@app.get("/api/country", response_model=dict[str, list[Country]])
async def get_countries(current_user: User = Depends(get_current_active_user)) -> dict[str, list[Country]]:
    return {'countries': [
        Country(id=1, nameInSwedish="Sverige", nameInEnglish="Sweden"),
        Country(id=2, nameInSwedish="Norge", nameInEnglish="Norway"),
        Country(id=3, nameInSwedish="Finland", nameInEnglish="Finland"),
        Country(id=4, nameInSwedish="Danmark", nameInEnglish="Denmark"),
        Country(id=5, nameInSwedish="Island", nameInEnglish="Iceland"),
        Country(id=6, nameInSwedish="Cypern", nameInEnglish="Cyprus")
    ]}
