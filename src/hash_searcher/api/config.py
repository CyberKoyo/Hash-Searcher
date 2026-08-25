import os

from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def key(env_var: str) -> str | None:
    """Read an API key at call time.

    Module-level constants froze whatever the environment held at import.
    PROVIDERS is built at import too, so a key set later was invisible to
    check_env and to every request header built from these values.
    """
    return os.getenv(env_var)
