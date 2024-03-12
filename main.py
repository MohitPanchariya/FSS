from itsdangerous import URLSafeSerializer, SignatureExpired, BadSignature
from fastapi import FastAPI, HTTPException, status, Form, UploadFile
from fastapi import BackgroundTasks, Depends, Request, Response
from psycopg2.extras import DictCursor, register_uuid
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from globals import USERSPACES
from pydantic import BaseModel
from dotenv import load_dotenv
from secrets import token_hex
from typing import Annotated
from typing import Optional
import hashlib
import os
import shutil
import helpers
import rdiff
import tempfile
import psycopg2
import bcrypt
import uuid
import datetime
import psycopg2.pool

dbParameters = {}
register_uuid()

SECRET_KEY = token_hex()
serializer = URLSafeSerializer(SECRET_KEY)

db_connection_pool = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global dbParameters
    global db_connection_pool
    load_dotenv(dotenv_path=".env")
    dbParameters["database"] = os.environ["DB_NAME"]
    dbParameters["user"] = os.environ["DB_USER"]
    dbParameters["password"] = os.environ["DB_PASSWORD"]
    dbParameters["host"] = os.environ["DB_HOST"]
    dbParameters["port"] = os.environ["DB_PORT"]

    # create the connection pool on startup
    db_connection_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=1, maxconn=10, **dbParameters,
        cursor_factory=DictCursor
    )
    yield
    # close the connections on application shutdown
    db_connection_pool.closeall()


app = FastAPI(lifespan=lifespan)


class UserLogin(BaseModel):
    email: str
    password: str


class UserRegister(BaseModel):
    email: str
    password: str
    username: str


class User:
    """
    User model for a user in the database.
    """

    def __init__(self, user_id: str, username: str, email: str, password: str):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password = password


def getDbConnection():
    return psycopg2.connect(**dbParameters, cursor_factory=DictCursor)


def extract_cookie(signed_cookie) -> Optional[str]:
    """
    Returns the cookie if it's valid. Else returns None.
    """
    try:
        cookie = serializer.loads(signed_cookie)
        return cookie
    except Exception as e:
        return None


def delete_expired_session(session_id):
    """
    Deletes the session with the given session_id from
    the database.
    """
    query = "DELETE FROM user_session WHERE id = %s"
    connection = db_connection_pool.getconn()
    cursor = connection.cursor()
    cursor.execute(query, (session_id,))
    cursor.close()
    connection.commit()
    db_connection_pool.putconn(connection)


def login_required(request: Request):
    """
    This function is used to check if a user is logged in
    by inspecting the user's cookie.
    If the request doesn't contain a cookie, HTTP 401 Unauthorized
    response is sent back to the client.
    If the request contains a cookie, but if the session has expired,
    HTTP 401 Unauthorized response is sent.
    If the cookie has been tampered with, there by invalidating the
    signature on the cookie, an HTTP 400 Bad request response is sent.
    """
    signed_session_id = request.cookies.get("session-id")
    if not signed_session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login required."
        )
    try:
        session_id = serializer.loads(signed_session_id)
        connection = db_connection_pool.getconn()
        cursor = connection.cursor()
        query = "SELECT * FROM user_session WHERE id = %s"
        cursor.execute(query, (session_id,))
        result = cursor.fetchone()
        if result:
            # session has expired
            if result["expires_at"] < datetime.datetime.now():
                delete_expired_session(session_id)
            # session is still valid
            else:
                return session_id
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


def get_user(user_email: str = None, user_id: str = None) -> Optional[User]:
    """
    Returns a User object if the user exists. Else returns None.
    If neither the user_email nor user_id is specified, the function returns None
    """
    if not user_email and not user_id:
        return None

    connection = db_connection_pool.getconn()
    cursor = connection.cursor()

    if user_id:
        query = "SELECT * from app_user where id = %s"
        cursor.execute(query, (user_id,))
    else:
        query = "SELECT * from app_user where email = %s"
        cursor.execute(query, (user_email,))

    user_data = cursor.fetchone()
    cursor.close()
    db_connection_pool.putconn(connection)

    if not user_data:
        return None
    return User(
        user_id=user_data["id"].hex,
        email=user_data["email"],
        username=user_data["username"],
        password=user_data["password"]
    )


def get_user_by_session(session_id: str) -> Optional[User]:
    """
    Returns a User object if the session exists. Else returns None.
    """
    connection = db_connection_pool.getconn()
    cursor = connection.cursor()
    query = "SELECT user_id from user_session where id = %s"
    cursor.execute(query, (session_id,))
    user_data = cursor.fetchone()
    cursor.close()
    db_connection_pool.putconn(connection)

    if not user_data["user_id"]:
        return None
    return get_user(user_id=user_data["user_id"])


def is_session_active(session_id: str) -> bool:
    """
    Returns True if the session is active and False otherwise.
    Deletes the session entry from the database if the session
    has expired.
    """
    connection = db_connection_pool.getconn()
    cursor = connection.cursor()
    query = "SELECT expires_at FROM user_session WHERE id = %s"
    cursor.execute(query, (session_id,))
    session_data = cursor.fetchone()
    cursor.close()
    db_connection_pool.putconn(connection)

    if session_data:
        # session has expired
        if session_data["expires_at"] < datetime.datetime.now():
            delete_expired_session(session_id)
            return False
        # session is still active
        else:
            return True


def create_session(
        user_id: str,
        session_id: str,
        created_at: datetime.datetime,
        expires_at: datetime.datetime
):
    """
    Inserts a session into the database.
    """
    connection = db_connection_pool.getconn()
    cursor = connection.cursor()
    query = "INSERT INTO user_session VALUES(%s, %s, %s, %s)"
    cursor.execute(query, (session_id, user_id, created_at, expires_at))
    cursor.close()
    connection.commit()
    db_connection_pool.putconn(connection)


def create_user(email: str, password: str, username: str) -> User:
    """
    Inserts a user into the database and returns back a User object.
    The password supplied must be a plain text password, this function
    hashes the password.
    """
    user_id = uuid.uuid4().hex
    # hash and salt the password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    connection = db_connection_pool.getconn()
    cursor = connection.cursor()
    query = "INSERT INTO app_user VALUES(%s, %s, %s, %s)"
    cursor.execute(query, (user_id, username, email, hashed_password))
    cursor.close()
    connection.commit()
    db_connection_pool.putconn(connection)

    return User(
        user_id=user_id,
        username=username,
        email=email,
        password=password
    )


@app.post("/api/v1/login")
def login(user_login: UserLogin, response: Response, request: Request):
    user = get_user(user_login.email)

    # user doesn't exist
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user not found"
        )
    else:
        session_cookie = request.cookies.get("session-id")
        session_id = extract_cookie(session_cookie)
        # If the session cookie is valid, check if the user already has an
        # active session against this session_id
        if session_id:
            session_active = is_session_active(session_id)
            if session_active:
                return {
                    "id": user.user_id,
                    "email": user.email
                }

        # validate the password
        password_valid = bcrypt.checkpw(
            user_login.password.encode(),
            user.password.encode()
        )
        if not password_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="email or password is incorrect"
            )
        # create a session for the user
        session_id = uuid.uuid4()
        signed_session_id = serializer.dumps(str(session_id))
        created_at = datetime.datetime.now()
        expires_at = created_at + datetime.timedelta(hours=1)
        # insert session into database
        create_session(user.user_id, session_id.hex, created_at, expires_at)

        response.set_cookie(
            key="session-id",
            value=signed_session_id,
            max_age=3600,
            expires=expires_at.replace(tzinfo=datetime.timezone.utc).timestamp()
        )

        return {
            "id": user.user_id,
            "email": user.email
        }


@app.post("/api/v1/register")
def register(user_register: UserRegister, response: Response):
    user = get_user(user_register.email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exists"
        )
    # create the user
    else:
        user = create_user(email=user_register.email, password=user_register.password,
                           username=user_register.username)
        response.status_code = status.HTTP_201_CREATED
        # User space/root user directory is named with a hash of the user's id
        userspace = hashlib.sha256(user.user_id.encode()).hexdigest()
        # If the user space doesn't exist already, create one
        os.makedirs(os.path.join(USERSPACES, userspace))
        return {
            "id": user.user_id,
            "username": user_register.username,
            "email": user_register.email
        }


# End point to upload a file to a user-space
@app.post("/api/v1/upload-file", status_code=status.HTTP_201_CREATED)
def upload_file(
        path_from_base: Annotated[str, Form()],
        file: UploadFile,
        session_id: Annotated[str | None, Depends(login_required)]
):
    user = get_user_by_session(session_id)

    # conn = getDbConnection()
    # cur = conn.cursor()
    #
    # query = "SELECT user_id FROM user_session WHERE id = %s"
    # cur.execute(query, (sessionId,))
    #
    # result = cur.fetchone()
    # userId = result["user_id"]
    #
    # cur.close()
    # conn.close()

    # sanitise the client provided path
    sanitised_path_from_base = helpers.sanitise_file_path(path_from_base)
    sanitised_file_name = helpers.sanitise_file_path(file.filename)

    userspace = hashlib.sha256(user.user_id.encode()).hexdigest()
    path_in_userspace = os.path.join(USERSPACES, userspace, sanitised_path_from_base)
    # create the directories inside the user space
    os.makedirs(path_in_userspace, exist_ok=True)

    # check if user provided path from base and file name correspond to a directory
    # inside the user space. If it does, the user will have to either delete the
    # directory or use a different file name to store the file.
    if os.path.isdir(os.path.join(path_in_userspace, sanitised_file_name)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Directory with the same name as the file exists in the" \
                   " provided file path. Either the directory must be deleted" \
                   " or the file must be renamed."
        )

    # create the file inside the user space
    with open(os.path.join(path_in_userspace, sanitised_file_name), "wb") as out:
        shutil.copyfileobj(file.file, out)

    return {
        "path_in_user_dir": os.path.relpath(
            os.path.join(path_in_userspace, sanitised_file_name),
            os.path.join(USERSPACES, userspace)
        )
    }


# End point to get the signature file for a particular file in a user-space
@app.get("/api/v1/path/{file_path: path}")
def getSigFile(file_path: str, sessionId: Annotated[str | None, Depends(login_required)]):
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

    sanitisedPath = helpers.sanitise_file_path(file_path)

    basePath = os.path.split(sanitisedPath)[0]
    filename = os.path.split(sanitisedPath)[1]

    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()

    # check if the file exists
    if (not os.path.exists(os.path.join(USERSPACES, userSpace, sanitisedPath))):
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
        sessionId: Annotated[str | None, Depends(login_required)]
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

    sanitisedPath = helpers.sanitise_file_path(file_path)

    basePath = os.path.split(sanitisedPath)[0]

    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()

    # check if the file exists
    if (not os.path.exists(os.path.join(USERSPACES, userSpace, sanitisedPath))):
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
        sessionId: Annotated[str | None, Depends(login_required)]
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

    sanitisedPath = helpers.sanitise_file_path(file_path)

    basePath = os.path.split(sanitisedPath)[0]
    filename = os.path.split(sanitisedPath)[1]

    userSpace = hashlib.sha256(userId.hex.encode()).hexdigest()

    # check if the file exists
    if (not os.path.exists(os.path.join(USERSPACES, userSpace, sanitisedPath))):
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
            blockSize=1024,  # default block size used to create the sig file
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
