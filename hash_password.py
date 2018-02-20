#this is the hashing function I use to protext the customer PIN.
#as you see, it's an sha256 hash at 500k iterations

import hashlib

def hash_password(password, hash_salt):
    pw = password.encode()
    salt = hash_salt.encode()
    hashword = hashlib.pbkdf2_hmac('sha256', pw, salt, 500000)
    return hashword
