from fastapi import FastAPI, HTTPException, status, Form, UploadFile
from fastapi import BackgroundTasks, Depends, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Annotated
import hashlib, os, shutil, helpers, rdiff, tempfile
from globals import USERSPACES
import psycopg2
from psycopg2.extras import DictCursor, register_uuid
import bcrypt
from contextlib import asynccontextmanager
import uuid
from itsdangerous import URLSafeSerializer, SignatureExpired, BadSignature
import datetime
from secrets import token_hex
from dotenv import load_dotenv

load_dotenv(dotenv_path="./env")
dbParameters = {}
register_uuid()

SECRET_KEY = token_hex()
serializer = URLSafeSerializer(SECRET_KEY)

@asynccontextmanager
async def lifespan(app: FastAPI):
    dbParameters["dbname"] = os.environ["DB_NAME"]
    dbParameters["user"] = os.environ["DB_USER"]
    dbParameters["password"] = os.environ["DB_PASSWORD"]
    dbParameters["host"] = os.environ["DB_HOST"]
    dbParameters["port"] = os.environ["DB_PORT"]
    yield

app = FastAPI(lifespan=lifespan)


class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    username: str

def getDbConnection():
    return psycopg2.connect(**dbParameters, cursor_factory=DictCursor)

def extractCookie(signedCookie):
    '''
    Returns the cookie if its valid. Else returns None.
    '''
    try:
        cookie = serializer.loads(signedCookie)
        return cookie
    except Exception as e:
        print(e)
        return False

def deleteExpiredSession(sessionId):
    conn = getDbConnection()
    cur = conn.cursor()

    query = "DELETE FROM user_session WHERE id = %s"
    cur.execute(query, (sessionId,))
    conn.commit()
    cur.close()
    conn.close()

def loginRequired(request: Request):
    signedsessionId = request.cookies.get("session-id")
    if not signedsessionId:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login required."
        )
    try:
        sessionId = serializer.loads(signedsessionId)
        conn = getDbConnection()
        cur = conn.cursor()

        query = "SELECT expires_at FROM user_session WHERE id = %s"
        cur.execute(query, (sessionId,))

        result = cur.fetchone()

        if result:
            # session has expired
            if result["expires_at"] < datetime.datetime.now():
                deleteExpiredSession(sessionId)
                cur.close()
                conn.close()
            # session is still valid
            else:
                return sessionId
        else:
            raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session expired. Login again."
        )
    except SignatureExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session expired. Login again."
        )
    except BadSignature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session-id"
        )

@app.post("/api/v1/login")
def login(userLogin: UserLogin, response: Response, request: Request):
    conn = getDbConnection()
    cur = conn.cursor()
    # Check if user exists
    query = "SELECT id, email, password from app_user where email = %s"
    cur.execute(query, (userLogin.email,))

    userData = cur.fetchone()
    # user doesn't exist
    if not userData:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user not found"
        )
    else:
        sessionCookie = request.cookies.get("session-id")
        print(f"received cookie: {sessionCookie}")
        sessionId = extractCookie(sessionCookie)
        print(sessionId)
        # If the session cookie is valid, check if the user already has an
        # active session against this sessionId
        if sessionId:
            query = "SELECT id,expires_at FROM user_session WHERE id = %s"
            cur.execute(query, (sessionId,))

            session = cur.fetchone()
            if session:
                # session has expired
                if session["expires_at"] < datetime.datetime.now():
                    deleteExpiredSession(sessionId)
                # session is still valid
                else:
                    print("user already in session")
                    return {
                    "id": str(userData["id"]),
                    "email": userData["email"]
                }

            
        # validate the password
        passwordIsValid = bcrypt.checkpw(
            userLogin.password.encode(),
            userData["password"]
        )
        if not passwordIsValid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="email or password is incorrect"
            )
        # create a session for the user
        sessionId = uuid.uuid4()
        signedSessionId = serializer.dumps(str(sessionId))
        print(f"signed session cookie = {signedSessionId}")
        createdAt = datetime.datetime.now()
        expiresAt = createdAt + datetime.timedelta(hours=1)
        print(expiresAt)
        # insert session into database
        query = "INSERT INTO user_session VALUES(%s, %s, %s, %s)"
        cur.execute(
            query,
            (sessionId, userData["id"], createdAt, expiresAt)
        )

        cur.close()
        conn.commit()
        conn.close()

        response.set_cookie(
            key="session-id",
            value=signedSessionId,
            max_age=3600,
            expires=expiresAt.replace(tzinfo=datetime.timezone.utc).timestamp()
        )

        return {
            "id": str(userData["id"]),
            "email": userData["email"]
        }
    

@app.post("/api/v1/register")
def register(userRegister: UserRegister, response: Response):
    conn = getDbConnection()
    cur = conn.cursor()
    # Check if user is already registered
    query = "SELECT email from app_user where email = %s"
    cur.execute(query, (userRegister.email,))

    userExists = cur.fetchone()

    if userExists:
        cur.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exists"
        )
    # create the user
    else:
        userId = uuid.uuid4()
        hashedPassword = bcrypt.hashpw(userRegister.password, bcrypt.gensalt())
        print(hashedPassword)
        query = "INSERT INTO app_user VALUES (%s, %s, %s, %s)"
        cur.execute(
            query,
            (userId, userRegister.username, userRegister.email, hashedPassword)
        )
        cur.close()
        conn.commit()
        conn.close()
        response.status_code = status.HTTP_201_CREATED

        # User space/root user directory is named with a hash of the user's id
        hash = hashlib.sha256(userId.hex.encode()).hexdigest()
        # If the user space doesn't exist already, create one
        os.makedirs(os.path.join(USERSPACES, hash))
        return {
            "id": userId.hex,
            "username": userRegister.username,
            "email": userRegister.email
        }

# End point to upload a file to a user-space
@app.post("/api/v1/upload-file", status_code=status.HTTP_201_CREATED)
def uploadFile(
    path_from_base: Annotated[str, Form()],
    file: UploadFile,
    sessionId: Annotated[str | None, Depends(loginRequired)]
):
    conn = getDbConnection()
    cur = conn.cursor()

    query = "SELECT user_id FROM user_session WHERE id = %s"
    cur.execute(query, (sessionId,))

    result = cur.fetchone()
    userId = result["user_id"]

    cur.close()
    conn.close()

    # sanitise the client provided path
    sanitisedPathFromBase = helpers.sanitiseFilepath(path_from_base)
    sanitisedFileName = helpers.sanitiseFilepath(file.filename)

    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()
    pathInUserSpace = os.path.join(USERSPACES, userSpace, sanitisedPathFromBase)
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
            os.path.join(USERSPACES, userSpace)
        )
    }

# End point to get the signature file for a particular file in a user-space
@app.get("/api/v1/path/{file_path: path}")
def getSigFile(file_path: str, sessionId: Annotated[str | None, Depends(loginRequired)]):
    '''
    This endpoint is used to get a signature file in a user space for the 
    provided file.
    The client can then use the signature file to compute a delta file and
    send a request to the server to update the file.
    '''
    
    conn = getDbConnection()
    cur = conn.cursor()

    query = "SELECT user_id FROM user_session WHERE id = %s"
    cur.execute(query, (sessionId,))

    result = cur.fetchone()
    userId = result["user_id"]

    cur.close()
    conn.close()

    sanitisedPath = helpers.sanitiseFilepath(file_path)

    basePath = os.path.split(sanitisedPath)[0]
    filename = os.path.split(sanitisedPath)[1]
    
    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()

    # check if the file exists
    if(not os.path.exists(os.path.join(USERSPACES, userSpace, sanitisedPath))):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )
    
    # create the signatures directory if it doesn't exist
    print(os.path.join(USERSPACES, userSpace, basePath, ".signatures"))
    os.makedirs(os.path.join(USERSPACES, userSpace, basePath, ".signatures"), exist_ok=True)

    # create the signature file for the requested file and store it in the signatures directory
    checksum = rdiff.signature.Checksum()
    signature = rdiff.signature.Signature(checksum)
    signature.createSignature(
        basisFilePath=os.path.join(USERSPACES, userSpace, sanitisedPath),
        sigFilePath=os.path.join(USERSPACES, userSpace, basePath, ".signatures", filename)
    )

    return FileResponse(
        os.path.join(USERSPACES, userSpace, basePath, ".signatures", filename), 
        filename=f"{filename}.sig",
        media_type="application/octet-stream"
    )

# End point to push changes to a file in a user-space
@app.patch("/api/v1/update-file")
def patchFile(
    file_path: Annotated[str, Form()],
    delta_file: UploadFile,
    sessionId: Annotated[str | None, Depends(loginRequired)]
):
    '''
    This endpoint is used to update a file in a user-space. The client needs
    to provide a user email to identify the user space. Along with this,
    the client also needs to send a delta file, representing the changes to be
    made to the file.
    The file to be updated is identified by the file_path, which is
    relative path from base dir + filename.
    '''
    conn = getDbConnection()
    cur = conn.cursor()

    query = "SELECT user_id FROM user_session WHERE id = %s"
    cur.execute(query, (sessionId,))

    result = cur.fetchone()
    userId = result["user_id"]

    cur.close()
    conn.close()
    
    sanitisedPath = helpers.sanitiseFilepath(file_path)

    basePath = os.path.split(sanitisedPath)[0]

    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()

    # check if the file exists
    if(not os.path.exists(os.path.join(USERSPACES, userSpace, sanitisedPath))):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )
    
    # Perform the patch operation
    try:

        # Due to a limitation in the rdiff package, it requires file paths and
        # not file like objects, the delta_file needs to be saved
        # temporarily on the server to perform the file patch operation.

        # create a temporary delta file
        tempDeltaFile = tempfile.NamedTemporaryFile(mode="wb", delete=False)
        shutil.copyfileobj(delta_file.file, tempDeltaFile)
        tempDeltaFile.close()

        # create a temporary out file to store the updated file
        tempOutFile = tempfile.NamedTemporaryFile(
            mode="wb", delete=False,
            dir=os.path.join(USERSPACES, userSpace, basePath)
        )

        patcher = rdiff.patch.Patch()
        patcher.patchFile(
            tempDeltaFile.name,
            os.path.join(USERSPACES, userSpace, sanitisedPath),
            tempOutFile.name
        )   

        tempOutFile.close()

        # Atomically rename the temporary file to the actual filename
        os.replace(tempOutFile.name, os.path.join(USERSPACES, userSpace, sanitisedPath))
    except Exception:
        # remove the temp updated file
        os.remove(tempOutFile.name)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid delta file."
        )
    finally:
        # remove the temp delta file
        os.remove(tempDeltaFile.name)
        
    return {
        "path_in_user_dir": os.path.relpath(
            os.path.join(USERSPACES, userSpace, sanitisedPath),
            os.path.join(USERSPACES, userSpace)
        )
    }


def deleteTempDeltaFile(filepath):
    '''
    This function is used to delete the temporary delta file created when
    the client makes a request to the /api/v1/pull-change route.
    '''
    os.remove(filepath)

# Endpoint to pull changes for a file in a user-space
@app.post("/api/v1/pull-change")
def getDeltaFile(
    file_path: Annotated[str, Form()],
    sig_file: UploadFile,
    backgroundTasks: BackgroundTasks,
    sessionId: Annotated[str | None, Depends(loginRequired)]
):
    '''
    This endpoint is used to get a delta file for a file specified by the client.
    The delta file is produced against the signature file provided by the client
    and sent back to the client. The client can then use this delta file to patch
    the file to be updated on the client machine. Thus, the server and client
    now have the same version of the file.
    '''
    conn = getDbConnection()
    cur = conn.cursor()

    query = "SELECT user_id FROM user_session WHERE id = %s"
    cur.execute(query, (sessionId,))

    result = cur.fetchone()
    userId = result["user_id"]

    cur.close()
    conn.close()
    
    sanitisedPath = helpers.sanitiseFilepath(file_path)

    basePath = os.path.split(sanitisedPath)[0]
    filename = os.path.split(sanitisedPath)[1]

    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()

    # check if the file exists
    if(not os.path.exists(os.path.join(USERSPACES, userSpace, sanitisedPath))):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )
    
    # Due to a limitation in the rdiff package (it requires file paths and
    # not file like objects)the sig_file needs to be saved
    # temporarily on the server to create the delta file

    # create a temporary signature file
    tempSigFile = tempfile.NamedTemporaryFile(mode="wb", delete=False)
    shutil.copyfileobj(sig_file.file, tempSigFile)
    tempSigFile.close()

    # create a temporary file to store the delta file
    tempDeltaFile = tempfile.NamedTemporaryFile(
        mode="wb", delete=False,
        dir=os.path.join(USERSPACES, userSpace, basePath)
    )

    # Populate the delta file
    try:
        checksum = rdiff.signature.Checksum()
        delta = rdiff.delta.Delta()
        delta.createDeltaFile(
            inFilePath=os.path.join(USERSPACES, userSpace, sanitisedPath),
            deltaFilePath=tempDeltaFile.name,
            sigFielPath=tempSigFile.name,
            blockSize=1024, # default block size used to create the sig file
            checksum=checksum
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature file."
        )
    finally:
        # remove the temp signature file
        os.remove(tempSigFile.name)
        
    # Background task to delete the temporary delta file produced
    backgroundTasks.add_task(deleteTempDeltaFile, tempDeltaFile.name)  

    return FileResponse(
        os.path.join(USERSPACES, userSpace, basePath, tempDeltaFile.name), 
        filename=f"{filename}.delta",
        media_type="application/octet-stream"
    )