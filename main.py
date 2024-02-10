from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import hashlib
import os

app = FastAPI()

class User(BaseModel):
    email: str


# End point to create a new user
@app.post("/api/v1/users", status_code=status.HTTP_201_CREATED)
def createUser(user: User) -> User:
    '''
    This endpoint creates a new user. Essentially,
    this involves creating a user-space/user-root
    directory.
    The user-root directory is named using a 
    SHA-256 hash of the email associated with the user.
    '''
    # This hash will be the name of the user root dir
    hash = hashlib.sha256(user.email.encode()).hexdigest()
    # Check if user dir already exists. This indicates the
    # user space is alread created
    userSpaceDir = os.path.join(".", "user-spaces")
    if(os.path.isdir(os.path.join(userSpaceDir, hash))):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists."
        )
    
    # If the user space doesn't exist already, create one
    os.makedirs(os.path.join(userSpaceDir, hash))
    return user
