import os
import re
import sys

from config import TMP_DIR


def b64_url_to_std(val: str) -> str:
    replacements = [
        (r"\u002d", "+"),
        (r"\x5f", "/"),
    ]
    for pattern, repl in replacements:
        val = re.sub(pattern, repl, val, 0)
    return val


def b64_std_to_url(val: str) -> str:
    replacements = [
        (r"\+", "-"),
        (r"\/", "_"),
        (r"=+$", ""),
    ]
    for pattern, repl in replacements:
        val = re.sub(pattern, repl, val, 0)
    return val

# This is good enough
def safe_name(val: str) -> str:
    replacements = [
        (r"<", ""),
        (r">", ""),
        (r":", ""),
        (r"\/", ""),
        (r"\\", ""),
        (r"\|", ""),
        (r"\?", ""),
        (r"\*", ""),
        (r"\"", ""),
        (r",", ""),
    ]
    for pattern, repl in replacements:
        val = re.sub(pattern, repl, val, 0)
    return val


def print_with_asterisk(*vals: list[str]) -> None:
    print("*" * os.get_terminal_size().columns)
    for val in vals:
        print(val)


def delete_temp_files() -> None:
    if TMP_DIR != "./tmp":
        print("Temp file is not the default")
        sys.exit()
    if not os.path.exists(TMP_DIR):
        return
    for file in os.listdir(TMP_DIR):
        os.remove(f"{TMP_DIR}/{file}")
