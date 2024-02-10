from fastapi import FastAPI, HTTPException, status, Form, UploadFile
from pydantic import BaseModel
from typing import Annotated
import hashlib
import os
import shutil
import helpers

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
    # Check if user already exists.
    if(helpers.userExists(user.email)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists."
        )
    
    userSpaceDir = os.path.join(".", "user-spaces")
    # User space/root user directory is named with a hash of the user's email
    hash = hashlib.sha256(user.email.encode()).hexdigest()
    # If the user space doesn't exist already, create one
    os.makedirs(os.path.join(userSpaceDir, hash))
    return user

# End point to upload a file to a user-space
@app.post("/api/v1/upload-file", status_code=status.HTTP_201_CREATED)
def uploadFile(
    user_email: Annotated[str, Form()],
    path_from_base: Annotated[str, Form()],
    file: UploadFile
):
    # check if the user exists. If not, return an error
    if(not helpers.userExists(user_email)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User doesn't exist. User must be created first."
        )
    # sanitise the client provided path
    sanitisedPathFromBase = helpers.sanitiseFilepath(path_from_base)
    sanitisedFileName = helpers.sanitiseFilepath(file.filename)

    userSpace = hashlib.sha256(user_email.encode()).hexdigest()
    pathInUserSpace = os.path.join(".", "user-spaces", userSpace, sanitisedPathFromBase)
    # create the directories inside the user space
    os.makedirs(pathInUserSpace, exist_ok=True)

    # check if user provided path from base and file name correspond to a directory
    # inside the user space. If it does, the user will have to either delete the
    # directory or use a different file name to store the file.
    if(os.path.isdir(os.path.join(pathInUserSpace, sanitisedFileName))):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Directory with the same name as the file exists in the"\
                    " provided file path. Either the directory must be deleted"\
                    " or the file must be renamed."
        )

    # create the file inside the user space
    with open(os.path.join(pathInUserSpace, sanitisedFileName), "wb") as out:
        shutil.copyfileobj(file.file, out)

    return {
        "path_in_user_dir": os.path.relpath(
            os.path.join(pathInUserSpace, sanitisedFileName),
            os.path.join(".", "user-spaces", userSpace)
        )
    }

