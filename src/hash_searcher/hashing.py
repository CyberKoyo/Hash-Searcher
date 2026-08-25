import hashlib
import pyzipper

from .api.registry import available, missing_keys


def check_env() -> bool:
    """Warn about absent keys and carry on. Returns False if nothing can run.

    This used to sys.exit(1) unless all four keys were present, so a VT-only
    setup could not run at all.
    """
    missing = missing_keys()
    if missing:
        print(f"Warning: missing environment variables: {', '.join(missing)}")
        print("Those sources will be skipped.")

    usable = available()
    if not usable:
        print("Error: no usable sources. Set at least one API key in .env.")
        return False

    print(f"Sources enabled: {', '.join(p.name for p in usable)}")
    return True

BUF = 65536


def get_zip_hash(file_path: str, password: str | None = None) -> list[str]:
    """sha256 of every file inside a ZIP, or of the file itself if not a ZIP.

    Returns one digest per member in archive order. Directory entries are
    skipped. Members that cannot be read (wrong password, corruption) are
    reported and omitted rather than aborting the whole archive.

    password is a parameter so this is testable; when it is None the function
    prompts interactively. A future task moves that prompt into the CLI layer.
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
