import os

def relative_path(path: str) -> str:
    script_dir = os.path.dirname(__file__)
    return os.path.join(script_dir, path)

