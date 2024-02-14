import json
import sys
import os

DIR_CONFIG_PATH = os.path.join(".", "dir-config.json")

if not os.path.exists(DIR_CONFIG_PATH):
    print(f"dir-config.json not found. Exiting the program")
    sys.exit()

with open(DIR_CONFIG_PATH, "r") as file:
    dir_config = json.load(file)

USERSPACES = os.path.normpath(dir_config["user-spaces"])
