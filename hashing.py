import hashlib
import sys
import pyzipper

from api.config import total_api_key, ipdb_api_key, otx_api_key

def check_env():
    keys = {'TOTAL_KEY': total_api_key, "IPDB_KEY": ipdb_api_key,'OTX_KEY': otx_api_key}
    missing = [k for k,v in keys.items() if not v]
    if missing:
        print(f"Error: Missing envrionment variables: {', '.join(missing)}")
        sys.exit(1)
    else:
        print('API Keys loaded successfully.')
#Gets the hash from a zipped file given the password. Will regularly hash recursive ZIPs (ZIPS in ZIPS).
def get_zip_hash(file_path):
    sha256 = hashlib.sha256()
    buf = 65536
    if pyzipper.is_zipfile(file_path):
        print(f"Detecting ZIP file: {file_path}")
        password = input("Enter the password for the ZIP file: ")
        try:
            with pyzipper.AESZipFile(file_path, 'r')as z:
                if password:
                    z.setpassword(password.encode())
                if not z.namelist():
                        print(f'Empty ZIP file: {file_path}')
                        return
                for filename in z.namelist():
                    if filename.endswith('/'):
                        continue
                    print(f"Hashing internal file: {filename}")
                    try:
                        with z.open(filename, pwd=password.encode()) as f:
                            while True:
                                chunk = f.read(buf)
                                if not chunk:
                                    break
                                sha256.update(chunk)
                            final_hash = sha256.hexdigest()
                            print(f"Result: {final_hash}")
                            return final_hash
                    except RuntimeError as e:
                        if "password" in str(e).lower():
                            print(f'Error: Incorrect password for {filename}')
                        else:
                            print(f'Error reading {filename}: {e}')
        except Exception as e:
            print(f'Error opening ZIP: {e}')
    else:  
        return get_reg_hash()

def get_reg_hash():
    sha256 = hashlib.sha256()
    buf = 65536
    with open(sys.argv[1], 'rb') as f:
        while (data := f.read(buf)):
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()