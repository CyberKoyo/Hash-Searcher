import hashlib
import sys
import pyzipper

from .api.config import total_api_key, ipdb_api_key, otx_api_key, censys_api_key

def check_env():
    keys = {
        'TOTAL_KEY': total_api_key,
        'IPDB_KEY': ipdb_api_key,
        'OTX_KEY': otx_api_key,
        'CENSYS_KEY': censys_api_key,
    }
    missing = [k for k,v in keys.items() if not v]
    if missing:
        print(f"Error: Missing environment variables: {', '.join(missing)}")
        sys.exit(1)
    else:
        print('API Keys loaded successfully.')

BUF = 65536


def get_zip_hash(file_path: str, password: str | None = None) -> list[str]:
    """sha256 of every file inside a ZIP, or of the file itself if not a ZIP.

    Returns one digest per member in archive order. Directory entries are
    skipped. Members that cannot be read (wrong password, corruption) are
    reported and omitted rather than aborting the whole archive.

    password is a parameter rather than an input() call so this is testable;
    cli.py prompts when a ZIP is detected and none was supplied.
    """
    if not pyzipper.is_zipfile(file_path):
        return [get_reg_hash(file_path)]

    print(f"Detecting ZIP file: {file_path}")
    if password is None:
        password = input("Enter the password for the ZIP file: ")
    pwd = password.encode() if password else None

    digests: list[str] = []
    try:
        with pyzipper.AESZipFile(file_path, 'r') as z:
            if pwd:
                z.setpassword(pwd)
            names = z.namelist()
            if not names:
                print(f'Empty ZIP file: {file_path}')
                return []
            for filename in names:
                if filename.endswith('/'):
                    continue
                print(f"Hashing internal file: {filename}")
                # A fresh digest per member. Sharing one object made every
                # hash after the first a running total of its predecessors.
                sha256 = hashlib.sha256()
                try:
                    with z.open(filename, pwd=pwd) as f:
                        while chunk := f.read(BUF):
                            sha256.update(chunk)
                except RuntimeError as e:
                    if "password" in str(e).lower():
                        print(f'Error: Incorrect password for {filename}')
                    else:
                        print(f'Error reading {filename}: {e}')
                    continue
                digest = sha256.hexdigest()
                print(f"Result: {digest}")
                digests.append(digest)
    except Exception as e:
        print(f'Error opening ZIP: {e}')
        return []

    return digests


def get_reg_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while data := f.read(BUF):
            sha256.update(data)
    return sha256.hexdigest()