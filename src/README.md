# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- View activity rosters without signing in
- Sign in as a teacher to register or unregister students

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Add teacher accounts to `teachers.json`. Store only password hashes, never
   plaintext passwords. From the `src` directory, generate a salt and hash for
   each assigned password with:

   ```
   python -c "from app import hash_password; print(hash_password(input('Teacher password: ')))"
   ```

   Add each generated `salt` and `password_hash` alongside the teacher's
   `username` in the file's `teachers` list.

3. Set a random session-signing secret of at least 32 characters and start the
   application:

   ```
   export SESSION_SECRET="$(openssl rand -hex 32)"
   uvicorn app:app --reload
   ```

   When serving the app over HTTPS, also set `COOKIE_SECURE=true` so browsers
   send the teacher session cookie only over secure connections.

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| GET    | `/auth/me`                                                        | Check whether the current browser is signed in as a teacher          |
| POST   | `/auth/login`                                                     | Sign in with a teacher username and password                         |
| POST   | `/auth/logout`                                                    | Sign out and clear the teacher session                               |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Teacher-only student registration                                    |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Teacher-only student removal                                      |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

Activity data is stored in memory and resets when the server restarts. Teacher
credentials are stored in `teachers.json` as salted PBKDF2-SHA256 password
hashes. The session cookie is HTTP-only, signed, expires after eight hours, and
uses `SameSite=Strict`.
