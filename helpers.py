import os


def sanitise_file_path(file_path: str) -> str:
    """
    This function takes in a file path and sanitises it to get rid of traversals
    to parent directories, and redundant separators. It finally returns back a
    path which doesn't include file traversals and is it safe to use.
    """
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
    return os.path.relpath(os.path.normpath(os.path.join("/", file_path)), "/")