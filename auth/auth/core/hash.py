import hashlib


def get_hash(input_string: str, solt: str) -> str:
    return hashlib.sha256(str.encode(input_string + solt)).hexdigest()
