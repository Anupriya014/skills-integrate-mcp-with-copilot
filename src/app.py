"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

current_dir = Path(__file__).parent
teachers_file = current_dir / "teachers.json"
logger = logging.getLogger(__name__)
session_cookie = "teacher_session"
session_lifetime_seconds = 8 * 60 * 60
password_iterations = 310_000

app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


def hash_password(password: str) -> dict[str, str]:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, password_iterations
    )
    return {"salt": salt.hex(), "password_hash": password_hash.hex()}


def load_teachers() -> list[dict[str, str]]:
    try:
        data = json.loads(teachers_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        logger.exception("Unable to read teacher credentials")
        raise HTTPException(
            status_code=503,
            detail="Teacher sign-in is unavailable because its credential file "
            "could not be read.",
        ) from error

    if not isinstance(data, dict) or not isinstance(data.get("teachers"), list):
        raise HTTPException(
            status_code=503,
            detail="Teacher credentials must be a JSON object with a teachers list.",
        )

    teachers = data["teachers"]
    if any(
        not isinstance(teacher, dict)
        or not isinstance(teacher.get("username"), str)
        or not isinstance(teacher.get("salt"), str)
        or not isinstance(teacher.get("password_hash"), str)
        for teacher in teachers
    ):
        raise HTTPException(
            status_code=503,
            detail="A teacher credential entry is invalid.",
        )
    return teachers


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)
    except ValueError:
        return False

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, password_iterations
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def get_session_secret() -> bytes:
    secret = os.getenv("SESSION_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(
            status_code=503,
            detail="Teacher sign-in is not configured. Set SESSION_SECRET to a "
            "random value of at least 32 characters.",
        )
    return secret.encode("utf-8")


def encode_session(username: str) -> str:
    payload = json.dumps(
        {"username": username, "expires": int(time.time()) + session_lifetime_seconds},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        get_session_secret(), encoded_payload.encode("ascii"), hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"


def decode_session(token: str) -> str | None:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        expected_signature = hmac.new(
            get_session_secret(), encoded_payload.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None

        payload = base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        )
        session = json.loads(payload)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if (
        not isinstance(session, dict)
        or not isinstance(session.get("username"), str)
        or not isinstance(session.get("expires"), int)
        or session["expires"] <= int(time.time())
    ):
        return None
    return session["username"]


def require_teacher(request: Request) -> str:
    token = request.cookies.get(session_cookie)
    if token is None:
        raise HTTPException(status_code=401, detail="Teacher sign-in required.")

    username = decode_session(token)
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher session is invalid or expired.")
    return username


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/login")
def login(credentials: LoginRequest, response: Response):
    teacher = next(
        (
            teacher
            for teacher in load_teachers()
            if teacher["username"] == credentials.username
        ),
        None,
    )
    if teacher is None or not verify_password(
        credentials.password, teacher["salt"], teacher["password_hash"]
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    response.set_cookie(
        key=session_cookie,
        value=encode_session(credentials.username),
        max_age=session_lifetime_seconds,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"username": credentials.username}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(
        key=session_cookie,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"message": "Logged out."}


@app.get("/auth/me")
def current_teacher(request: Request):
    token = request.cookies.get(session_cookie)
    if token is None:
        return {"authenticated": False}

    username = decode_session(token)
    if username is None:
        return {"authenticated": False}
    return {"authenticated": True, "username": username}


@app.post("/activities/{activity_name}/signup", dependencies=[Depends(require_teacher)])
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete(
    "/activities/{activity_name}/unregister",
    dependencies=[Depends(require_teacher)],
)
def unregister_from_activity(activity_name: str, email: str):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
