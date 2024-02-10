import os
import hashlib

def userExists(userEmail) -> bool:
    # This hash will be the name of the user root dir
    hash = hashlib.sha256(userEmail.encode()).hexdigest()
    # Check if user dir already exists. This indicates the
    # user space is alread created
    userSpaceDir = os.path.join(".", "user-spaces")
    if(os.path.isdir(os.path.join(userSpaceDir, hash))):
        return True
    return False

def sanitiseFilepath(filePath: str) -> str:
    '''
    This function takes in a file path and sanitises it to get rid of traversals
    to parent directories, and redundant separators. It finnaly returns back a 
    path which doesn't include file traversals and is it safe to use.
    '''
    # os.path.normpath returns a normalised path, collapsing relative paths
    # and getting rid of redundant separators.
    # E.g: file_path = "a/b/c/../test.txt" is equivalent to just a/b/test.txt.
    # os.path.normpath takes care of normalising the path into a path without
    # redundancies.
    # Since we are joining a "/" to the filePath passed, all the upper traversals
    # are ignored since /../../../... will always just resolve to /.
    # Then a relative path to "/" is returned. Hence, getting rid of the / in
    # the start of the normpath.
    # E.g filePath = ../../../test1/test2/../test.txt will
    # resolve to test1/test.txt.
    print(os.path.relpath(os.path.normpath(os.path.join("/", filePath)), "/"))
    return os.path.relpath(os.path.normpath(os.path.join("/", filePath)), "/")