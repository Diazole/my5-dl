# Configurable
HMAC_SECRET = ""
AES_KEY = ""
WVD_PATH = ""
DOWNLOAD_DIR = "./downloads"
TMP_DIR = "./tmp"
BIN_DIR = "./bin"
USE_BIN_DIR = True

# Don't touch
APP_NAME = "my5desktopng"
BASE_URL_MEDIA = "https://cassie.channel5.com/api/v2/media"
BASE_URL_SHOWS = "https://corona.channel5.com/shows"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
DEFAULT_HEADERS = {
    "Accept": "*/*",
    "User-Agent": USER_AGENT,
}
DEFAULT_JSON_HEADERS = {
    "Content-type": "application/json",
    "Accept": "*/*",
    "User-Agent": USER_AGENT,
}
