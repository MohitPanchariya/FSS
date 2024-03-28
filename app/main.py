from itsdangerous import SignatureExpired, BadSignature
from fastapi import FastAPI, HTTPException, status, Form, UploadFile
from fastapi import BackgroundTasks, Depends, Request, Response
from psycopg2.extras import DictCursor, register_uuid
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from globals import USERSPACES, serializer
from pydantic import BaseModel
from typing import Annotated
from models.user import User
from models.session import Session
import hashlib
import os
import shutil
import helpers
import rdiff
import tempfile
import psycopg2
import uuid
import datetime
import psycopg2.pool
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHashError

dbParameters = {}
register_uuid()

db_connection_pool = None
ph = PasswordHasher()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global dbParameters
    global db_connection_pool
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
        connection = db_connection_pool.getconn()
        session_id = serializer.loads(signed_session_id)
        cursor = connection.cursor()
        query = "SELECT * FROM user_session WHERE id = %s"
        cursor.execute(query, (session_id,))
        result = cursor.fetchone()
        if result:
            # session has expired
            if result["expires_at"] < datetime.datetime.now():
                Session.delete_session(db_conn=connection, session_id=session_id)
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
    finally:
        db_connection_pool.putconn(connection)


def create_sig_file(basis_file_path: str, sig_file_path: str):
    """
    This function creates a signature file, and saves it to
    sig_file_path.
    """
    checksum = rdiff.signature.Checksum()
    signature = rdiff.signature.Signature(checksum)
    signature.createSignature(
        basisFilePath=basis_file_path,
        sigFilePath=sig_file_path
    )


def create_delta_file(file_path: str, sig_file_path: str, delta_file_path: str):
    """
    This function creates a delta file for the file located at file_path,
    against the signature file located at sig_file_path. The delta file is
    stored at delta_file_path
    """
    checksum = rdiff.signature.Checksum()
    delta = rdiff.delta.Delta()
    delta.createDeltaFile(
        inFilePath=file_path,
        deltaFilePath=delta_file_path,
        sigFielPath=sig_file_path,
        blockSize=1024,  # default block size used to create the sig file
        checksum=checksum
    )


def create_reverse_delta(
        file_path: str, updated_file_path: str,
        reverse_delta_path: str
):
    """
    Create a delta file that can be used to revert an updated file,
    back to the original file.
    Here, update_file_path is the path to the updated file and file_path
    is the path to the original file.
    """
    # create a temporary signature file
    temp_sig_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
    create_sig_file(
        basis_file_path=updated_file_path,
        sig_file_path=temp_sig_file.name
    )
    # create a delta file that will store the instruction to revert
    # the file located at updated_file_path to the file located at
    # file_path
    create_delta_file(
        file_path=file_path, sig_file_path=temp_sig_file.name,
        delta_file_path=reverse_delta_path
    )

    temp_sig_file.close()
    # delete the temp signature file
    os.remove(temp_sig_file.name)


def store_reverse_delta(
        file_path: str, updated_file_path: str,
        delta_dir_path: str,
):
    """
    Store a reverse delta file at the delta_dir_path, with a
    unique filename(uuid). Returns the path where the reverse
    delta file is stored.
    """
    reverse_delta_id = uuid.uuid4().hex
    # the head file stores the id's of all reverse delta's
    head_file = os.path.split(file_path)[1] + ".head"

    if not os.path.exists(delta_dir_path):
        os.makedirs(delta_dir_path)

    if not os.path.exists(os.path.join(delta_dir_path, head_file)):
        # create a file which will store the id's of different reverse delta's
        with open(os.path.join(delta_dir_path, head_file), "w"):
            pass
    # append the latest reverse delta's id to the head file
    with open(os.path.join(delta_dir_path, head_file), "a") as out:
        # parent_meta_id = out.readline()
        out.write(f"{reverse_delta_id}\n")

    reverse_delta = open(file=os.path.join(delta_dir_path, reverse_delta_id), mode="wb")
    create_reverse_delta(
        file_path=file_path, updated_file_path=updated_file_path,
        reverse_delta_path=reverse_delta.name
    )
    reverse_delta.close()
    return reverse_delta.name


def reverse_delta_ids(file_path: str):
    """
    Returns the list of all reverse delta id's for a
    given file. If there are no reverse delta's, returns an
    empty list
    """
    head_file = os.path.join(
        os.path.split(file_path)[0], "delta", (os.path.split(file_path)[1] + ".head")
    )
    ids = []
    if os.path.exists(head_file):
        with open(os.path.join(head_file), "r") as head:
            for reverse_delta_id in head:
                ids.append(reverse_delta_id.strip())

    return ids


@app.post("/api/v1/login")
def login(user_login: UserLogin, response: Response, request: Request):
    db_conn = db_connection_pool.getconn()
    user = User.get_user(db_conn=db_conn, user_email=user_login.email)
    # user doesn't exist
    if not user:
        db_connection_pool.putconn(db_conn)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user not found"
        )
    else:
        session_cookie = request.cookies.get("session-id")
        session_id = helpers.extract_cookie(session_cookie)
        # If the session cookie is valid, check if the user already has an
        # active session against this session_id
        if session_id:
            session_active = Session.is_session_active(db_conn=db_conn, session_id=session_id)
            if session_active:
                return {
                    "id": user.user_id,
                    "email": user.email
                }

        try:
            # validate the password
            ph.verify(hash=user.password, password=user_login.password)
        # password validation failed
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="email or password is incorrect"
            )
        # create a session for the user
        session_id = secrets.token_hex(nbytes=32)
        signed_session_id = serializer.dumps(str(session_id))
        created_at = datetime.datetime.now()
        expires_at = created_at + datetime.timedelta(days=30)
        # insert session into database
        Session.insert_into_db(
            db_conn=db_conn, session_id=session_id, user_id=user.user_id,
            created_at=created_at, expires_at=expires_at
        )
        db_connection_pool.putconn(db_conn)
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


@app.post("/api/v1/logout")
def logout(request: Request, response: Response, logout_everywhere: bool | None = None):
    session_id = helpers.extract_cookie(request.cookies.get("session-id"))
    if not session_id:
        return
    db_conn = db_connection_pool.getconn()
    if logout_everywhere:
        user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
        Session.delete_all_sessions(db_conn=db_conn, user_id=user.user_id)
    else:
        Session.delete_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)

    response.delete_cookie(key="session-id")
    return


@app.post("/api/v1/register")
def register(user_register: UserRegister, response: Response):
    db_conn = db_connection_pool.getconn()
    user = User.get_user(db_conn=db_conn, user_email=user_register.email)
    db_connection_pool.putconn(db_conn)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already exists"
        )
    # create the user
    else:
        db_conn = db_connection_pool.getconn()
        hashed_password = ph.hash(password=user_register.password)
        user = User.insert_user_to_db(
            user_id=uuid.uuid4(), username=user_register.username, email=user_register.email,
            hashed_password=hashed_password, db_conn=db_conn
        )
        db_connection_pool.putconn(db_conn)

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
    db_conn = db_connection_pool.getconn()
    user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)

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
def get_sig_file(file_path: str, session_id: Annotated[str | None, Depends(login_required)]):
    """
    This endpoint is used to get a signature file in a user space for the 
    provided file.
    The client can then use the signature file to compute a delta file and
    send a request to the server to update the file.
    """
    db_conn = db_connection_pool.getconn()
    user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)

    if not helpers.file_exists(user_id=user.user_id, file_path=file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )

    sanitised_path = helpers.sanitise_file_path(file_path)

    base_path = os.path.split(sanitised_path)[0]
    filename = os.path.split(sanitised_path)[1]

    userspace = hashlib.sha256(user.user_id.encode()).hexdigest()

    # create the signatures directory if it doesn't exist
    os.makedirs(os.path.join(USERSPACES, userspace, base_path, ".signatures"), exist_ok=True)

    # create the signature file for the requested file and store it in the signatures directory
    create_sig_file(
        basis_file_path=os.path.join(USERSPACES, userspace, sanitised_path),
        sig_file_path=os.path.join(USERSPACES, userspace, base_path, ".signatures", filename)
    )

    return FileResponse(
        os.path.join(USERSPACES, userspace, base_path, ".signatures", filename),
        filename=f"{filename}.sig",
        media_type="application/octet-stream"
    )


# End point to push changes to a file in a user-space
@app.patch("/api/v1/update-file")
def patch_file(
        file_path: Annotated[str, Form()],
        delta_file: UploadFile,
        session_id: Annotated[str | None, Depends(login_required)]
):
    """
    This endpoint is used to update a file in a user-space. The client needs
    to provide a user email to identify the user space. Along with this,
    the client also needs to send a delta file, representing the changes to be
    made to the file.
    The file to be updated is identified by the file_path, which is
    relative path from base dir + filename.
    """
    db_conn = db_connection_pool.getconn()
    user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)
    # check if the file exists
    if not helpers.file_exists(user_id=user.user_id, file_path=file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )

    sanitised_path = helpers.sanitise_file_path(file_path)

    base_path = os.path.split(sanitised_path)[0]

    userspace = hashlib.sha256(user.user_id.encode()).hexdigest()
    temp_out_file = None
    temp_delta_file = None
    # Perform the patch operation
    try:

        # Due to a limitation in the rdiff package, it requires file paths and
        # not file like objects, the delta_file needs to be saved
        # temporarily on the server to perform the file patch operation.

        # create a temporary delta file
        temp_delta_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
        shutil.copyfileobj(delta_file.file, temp_delta_file)
        temp_delta_file.close()

        # create a temporary out file to store the updated file
        temp_out_file = tempfile.NamedTemporaryFile(
            mode="wb", delete=False,
            dir=os.path.join(USERSPACES, userspace, base_path)
        )

        patcher = rdiff.patch.Patch()
        patcher.patchFile(
            temp_delta_file.name,
            os.path.join(USERSPACES, userspace, sanitised_path),
            temp_out_file.name
        )

        temp_out_file.close()

        file_path = os.path.join(USERSPACES, userspace, sanitised_path)
        delta_dir_path = os.path.join(USERSPACES, userspace, base_path, "delta")
        # store a reverse delta file
        store_reverse_delta(file_path=file_path, delta_dir_path=delta_dir_path, updated_file_path=temp_out_file.name)

        # Atomically rename the temporary file to the actual filename
        os.replace(temp_out_file.name, file_path)
    except Exception:
        # remove the temp updated file
        if temp_out_file:
            os.remove(temp_out_file.name)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid delta file."
        )
    finally:
        # remove the temp delta file
        if temp_delta_file:
            os.remove(temp_delta_file.name)

    return {
        "path_in_user_dir": os.path.relpath(
            os.path.join(USERSPACES, userspace, sanitised_path),
            os.path.join(USERSPACES, userspace)
        )
    }


def delete_temp_delta_file(filepath):
    """
    This function is used to delete the temporary delta file created when
    the client makes a request to the /api/v1/pull-change route.
    """
    os.remove(filepath)


# Endpoint to pull changes for a file in a user-space
@app.post("/api/v1/pull-change")
def get_delta_file(
        file_path: Annotated[str, Form()],
        sig_file: UploadFile,
        background_task: BackgroundTasks,
        session_id: Annotated[str | None, Depends(login_required)]
):
    """
    This endpoint is used to get a delta file for a file specified by the client.
    The delta file is produced against the signature file provided by the client
    and sent back to the client. The client can then use this delta file to patch
    the file to be updated on the client machine. Thus, the server and client
    now have the same version of the file.
    """
    db_conn = db_connection_pool.getconn()
    user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)

    if not helpers.file_exists(user_id=user.user_id, file_path=file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )

    sanitised_path = helpers.sanitise_file_path(file_path)

    base_path = os.path.split(sanitised_path)[0]
    filename = os.path.split(sanitised_path)[1]

    userspace = hashlib.sha256(user.user_id.encode()).hexdigest()

    # Due to a limitation in the rdiff package (it requires file paths and
    # not file like objects)the sig_file needs to be saved
    # temporarily on the server to create the delta file

    # create a temporary signature file
    temp_sig_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
    shutil.copyfileobj(sig_file.file, temp_sig_file)
    temp_sig_file.close()

    # create a temporary file to store the delta file
    temp_delta_file = tempfile.NamedTemporaryFile(
        mode="wb", delete=False,
        dir=os.path.join(USERSPACES, userspace, base_path)
    )

    # Populate the delta file
    try:
        create_delta_file(
            file_path=os.path.join(USERSPACES, userspace, sanitised_path),
            delta_file_path=temp_delta_file.name,
            sig_file_path=temp_sig_file.name
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature file."
        )
    finally:
        # remove the temp signature file
        os.remove(temp_sig_file.name)

    # Background task to delete the temporary delta file produced
    background_task.add_task(delete_temp_delta_file, temp_delta_file.name)

    return FileResponse(
        os.path.join(USERSPACES, userspace, base_path, temp_delta_file.name),
        filename=f"{filename}.delta",
        media_type="application/octet-stream"
    )


@app.get("/api/v1/reverse_delta_ids/{file_path: path}")
def get_reverse_delta_ids(file_path: str, session_id: Annotated[str | None, Depends(login_required)]):
    """
    Endpoint used to fetch a list of reverse delta ids for a given file in a userspace.
    This endpoint acts as an auxiliary endpoint for reverting a file back to a
    particular version.
    """
    db_conn = db_connection_pool.getconn()
    user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)

    if not helpers.file_exists(user_id=user.user_id, file_path=file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )

    sanitised_path = helpers.sanitise_file_path(file_path)

    userspace = hashlib.sha256(user.user_id.encode()).hexdigest()

    ids = reverse_delta_ids(os.path.join(USERSPACES, userspace, sanitised_path))

    return {
        "reverse_delta_ids": ids
    }


@app.get("/api/v1/download/reverse_delta/{file_path: str}/{reverse_delta_id: str}")
def download_reverse_delta(
        file_path: str, reverse_delta_id: str,
        session_id: Annotated[str | None, Depends(login_required)]
):
    """
    Endpoint to download the reverse delta for a given file and reverse delta id
    """
    db_conn = db_connection_pool.getconn()
    user = User.get_user_by_session(db_conn=db_conn, session_id=session_id)
    db_connection_pool.putconn(db_conn)

    if not helpers.file_exists(user_id=user.user_id, file_path=file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File with specified path not found"
        )

    sanitised_path = helpers.sanitise_file_path(file_path)

    userspace = hashlib.sha256(user.user_id.encode()).hexdigest()

    reverse_delta_path = os.path.join(
        USERSPACES, userspace, os.path.split(sanitised_path)[0], "delta", reverse_delta_id
    )

    if not os.path.exists(reverse_delta_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="reverse delta with specified id not found"
        )

    return FileResponse(
        reverse_delta_path,
        filename=reverse_delta_id,
        media_type="application/octet-stream"
    )
