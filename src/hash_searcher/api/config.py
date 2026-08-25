import os
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

total_api_key = os.getenv("TOTAL_KEY")
ipdb_api_key = os.getenv("IPDB_KEY")
otx_api_key = os.getenv("OTX_KEY")
censys_api_key = os.getenv("CENSYS_KEY")
