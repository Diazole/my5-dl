# Channel 5 (My5) Downloader
An AIO python script to download Channel 5 (My5) content.

## Requirements
* Python 3.6.*
* pip
* ffmpeg (https://github.com/FFmpeg/FFmpeg)
* mp4decrypt (https://github.com/axiomatic-systems/Bento4)
* yt-dlp (https://github.com/yt-dlp/yt-dlp)
* WVD file (https://github.com/rlaphoenix/pywidevine)

##  Install
```
pip install -r requirements.txt
```

## Usage
```
py .\my5-dl.py --download --subtitles --url "https://www.channel5.com/show/secrets-of-our-universe-with-tim-peake/season-1/the-planets"
```

## Arguments
```
-d, --download   Download content.
-s, --subtitles  Download subtitles.
-u, --url        URL of the episode to download.
```

## Config
Config is located in `config.py`

`HMAC_SECRET` - HMAC secret used to generate the authentication key for the content URL  
`AES_KEY` - AES key used to decrypt the data field of the API response  
`BIN_DIR` - Path to where your binaries installed  
`USE_BIN_DIR` - Flag indicating whether to use the binaries in the BIN_DIR path or your system/user path  
`DOWNLOAD_DIR` - Path to your download directory  
`TMP_DIR` - Path to your temp directory  
`WVD_PATH` - Path to your WVD file

## Retrieving Keys
The `HMAC_SECRET` and `AES_KEY` keys can be retrieved by opening `./keys/retrieve-keys.html` in your browser.

## Disclaimer

1. This script requires a Widevine RSA key pair to retrieve the decryption key from the license server.
2. This script is purely for educational purposes and should not be used to bypass DRM protected content.
