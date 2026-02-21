import os 
from dotenv import load_dotenv

load_dotenv()

total_api_key = os.getenv("TOTAL_KEY")
ipdb_api_key = os.getenv("IPDB_KEY")
otx_api_key = os.getenv("OTX_KEY")
censys_api_key = os.getenv("CENSYS_KEY")