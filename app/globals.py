import os
from secrets import token_hex
from itsdangerous import URLSafeSerializer

USERSPACES = os.environ.get('USERSPACES')

if not USERSPACES:
    raise Exception("USERSPACES environment variable not found.")

SECRET_KEY = token_hex()
serializer = URLSafeSerializer(SECRET_KEY)
