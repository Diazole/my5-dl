import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import hmac
import hashlib
from urllib.parse import urlparse
import requests

from pywidevine.pssh import PSSH
from pywidevine.device import Device
from pywidevine.cdm import Cdm

from Crypto.Cipher import AES
from utility import (
    b64_std_to_url,
    b64_url_to_std,
    delete_temp_files,
    print_with_asterisk,
    safe_name,
)
from config import (
    AES_KEY,
    APP_NAME,
    BASE_URL_MEDIA,
    BASE_URL_SHOWS,
    DEFAULT_HEADERS,
    DEFAULT_JSON_HEADERS,
    DOWNLOAD_DIR,
    HMAC_SECRET,
    TMP_DIR,
    USE_BIN_DIR,
    WVD_PATH,
)


def generate_episode_url(url: str) -> str | None:
    try:
        print("[*] Generating the episode URL...")
        path_segments = urlparse(url).path.strip("/").split("/")

        if path_segments[0] != "show":
            return

        if len(path_segments) == 2:
            show = path_segments[1]
            return f"{BASE_URL_SHOWS}/{show}/episodes/next.json?platform=my5desktop&friendly=1"
        if len(path_segments) == 4:
            show = path_segments[1]
            season = path_segments[2]
            episode = path_segments[3]
            return f"{BASE_URL_SHOWS}/{show}/seasons/{season}/episodes/{episode}.json?platform=my5desktop&friendly=1&linear=true"
        return None
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to get the episode URL: {ex}")
        raise


def get_content_info(episode_url: str) -> str:
    try:
        print("[*] Getting the encrypted content info...")
        r = requests.get(episode_url, headers=DEFAULT_JSON_HEADERS, timeout=10)
        if r.status_code != 200:
            print(
                f"[!] Received status code '{r.status_code}' when attempting to get the content ID"
            )
            return

        resp = json.loads(r.content)

        if resp["vod_available"] == False:
            print("[!] Episode is not available")
            return

        return (
            resp["id"],
            resp["sea_num"],
            str(resp["ep_num"]),
            resp["sh_title"],
            resp["title"],
        )
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to get the content ID: {ex}")
        raise


def generate_content_url(content_id: str) -> str:
    try:
        print("[*] Generating the content URL...")
        now = int(time.time() * 1000)
        timestamp = round(now / 1e3)
        c_url = f"{BASE_URL_MEDIA}/{APP_NAME}/{content_id}.json?timestamp={timestamp}"
        sig = hmac.new(base64.b64decode(HMAC_SECRET), c_url.encode(), hashlib.sha256)
        auth = base64.b64encode(sig.digest()).decode()
        return f"{c_url}&auth={b64_std_to_url(auth)}"
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to get the content URL: {ex}")
        raise


def decrypt_content(content: dict) -> str:
    try:
        print("[*] Decrypting the content response...")
        key_bytes = base64.b64decode(AES_KEY)
        iv_bytes = base64.b64decode(b64_url_to_std(content["iv"]))
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        data_bytes = base64.b64decode(b64_url_to_std(content["data"]))
        decrypted_data = cipher.decrypt(data_bytes)
        return decrypted_data[: -decrypted_data[-1]].decode()
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to decrypt the content info: {ex}")
        raise


def get_content_response(content_url: str) -> dict:
    try:
        print("[*] Getting content response...")
        r = requests.get(content_url, headers=DEFAULT_JSON_HEADERS, timeout=10)
        if r.status_code != 200:
            print(
                f"[!] Received status code '{r.status_code}' when attempting to get the content response"
            )
            return
        resp = json.loads(r.content)
        return json.loads(decrypt_content(resp))
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to get the content response: {ex}")
        raise


def get_first_rendition(decrypted_content: str) -> None:
    for asset in decrypted_content["assets"]:
        if asset["drm"] == "widevine":
            print_with_asterisk("[LICENSE URL]", asset["keyserver"])
            print_with_asterisk("[MPD URL]", asset["renditions"][0]["url"])

            original_mpd = asset["renditions"][0]["url"]
            content_id = decrypted_content["id"]
            default_mpd = original_mpd.replace(
                f"{content_id}_SD-tt.mpd", f"{content_id}.mpd"
            )
            subtitles_mpd = original_mpd.replace(
                f"{content_id}_SD-tt.mpd", f"{content_id}_subtitles.mpd"
            )

            print_with_asterisk("[SUBTITLES URL]", subtitles_mpd)

            return (
                asset["keyserver"],
                default_mpd,
                subtitles_mpd,
            )


def print_decrypted_content(decrypted_content: str):
    for asset in decrypted_content["assets"]:
        if asset["drm"] == "widevine":
            print_with_asterisk("[LICENSE URL]", asset["keyserver"])
            print_with_asterisk("[MPD URL]", asset["renditions"][0]["url"])

            for rendition in asset["renditions"]:
                print_with_asterisk("[MPD URL]", rendition["url"])


def get_pssh_from_mpd(mpd: str):
    try:
        print_with_asterisk("[*] Extracting PSSH from MPD...")
        r = requests.get(mpd, headers=DEFAULT_JSON_HEADERS, timeout=10)
        if r.status_code != 200:
            print(
                f"[!] Received status code '{r.status_code}' when attempting to get the MPD"
            )
            return

        return re.findall(r"<cenc:pssh>(.*?)</cenc:pssh>", r.text)[1]
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to get the content ID: {ex}")
        raise


def get_decryption_key(pssh: str, lic_url: str) -> str | None:
    cdm = None
    session_id = None
    try:
        print("[*] Getting decryption keys...")

        device = Device.load(WVD_PATH)
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        r = requests.post(lic_url, data=challenge, headers=DEFAULT_HEADERS, timeout=10)
        if r.status_code != 200:
            print(
                f"[!] Received status code '{r.status_code}' when attempting to get the license challenge"
            )
            return
        cdm.parse_license(session_id, r.content)

        decryption_key = None
        for key in cdm.get_keys(session_id):
            if key.type == "CONTENT":
                if decryption_key is None:
                    decryption_key = f"{key.kid.hex}:{key.key.hex()}"
                print_with_asterisk("[KEY]", f"{key.kid.hex}:{key.key.hex()}")
        return decryption_key
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to get the decryption keys: {ex}")
        raise
    finally:
        cdm.close(session_id)


def download_streams(mpd: str, show_title: str, episode_title: str) -> str:
    try:
        print_with_asterisk("[*] Downloading streams...")

        output_title = safe_name(f"{show_title}_{episode_title}")

        yt_dlp = "yt-dlp"
        if USE_BIN_DIR:
            yt_dlp = "./bin/yt-dlp.exe"

        os.makedirs(TMP_DIR, exist_ok=True)

        args = [
            yt_dlp,
            "--allow-unplayable-formats",
            "-q",
            "--no-warnings",
            "--progress",
            "-f",
            "bv,ba",
            mpd,
            "-o",
            f"{TMP_DIR}/encrypted_{output_title}.%(ext)s",
        ]
        subprocess.run(args, check=True)
        return output_title
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to download streams: {ex}")
        raise


def decrypt_streams(decryption_key: str, output_title: str) -> list:
    try:
        print("[*] Decrypting streams...")

        mp4_decrypt = "mp4decrypt"
        if USE_BIN_DIR:
            mp4_decrypt = "./bin/mp4decrypt.exe"

        files = []
        for file in os.listdir(TMP_DIR):
            if output_title in file:
                encrypted_file = f"{TMP_DIR}/{file}"
                file = file.replace("encrypted_", "decrypted_")
                output_file = f"{TMP_DIR}/{file}"
                files.append(output_file)
                args = [
                    mp4_decrypt,
                    "--key",
                    decryption_key,
                    encrypted_file,
                    output_file,
                ]
                subprocess.run(args, check=True)

        for file in os.listdir(TMP_DIR):
            if "encrypted_" in file:
                os.remove(f"{TMP_DIR}/{file}")
        return files
    except Exception as ex:
        print(f"[!] Exception thrown when attempting to decrypt the streams: {ex}")
        raise


def merge_streams(
    files: list,
    show_title: str,
    season_number: str,
    episode_number: str,
    episode_title: str,
    subtitles_url: str,
    dl_subtitles: bool,
):
    try:
        print("[*] Merging streams...")

        date_regex = r"(monday|tuesday|wednesday|thursday|friday) \d{0,2} (january|february|march|april|may|june|july|august|september|october|november|december)"
        if re.match(date_regex, episode_title, re.I):
            episode_title = ""

        if season_number is None:
            season_number = "01"
        if len(season_number) == 1:
            season_number = f"0{season_number}"
        if len(episode_number) == 1:
            episode_number = f"0{episode_number}"

        if "Episode " in episode_title:
            if len(show_title.split(":")) == 2:
                episode_title = show_title.split(":")[1]
            else:
                episode_title = ""

        season_number = f"S{season_number}"
        episode_number = f"E{episode_number}"

        if len(episode_title.split(":")) == 2:
            episode_title = episode_title.split(":")[1]

        if show_title == episode_title or (
            len(show_title.split(":")) == 2
            and show_title.split(":")[1] in episode_title
        ):
            episode_title = ""

        output_dir = f"{DOWNLOAD_DIR}/{safe_name(show_title)}"
        os.makedirs(output_dir, exist_ok=True)

        output_dir += " ".join(
            f"/{safe_name(show_title)} {season_number}{episode_number} {episode_title}".split()
        ).replace(" ", ".")

        mp4_decrypt = "ffmpeg"
        if USE_BIN_DIR:
            mp4_decrypt = "./bin/ffmpeg.exe"

        args = [
            mp4_decrypt,
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            files[0],
            "-i",
            files[1],
            "-c",
            "copy",
            f"{output_dir}.mp4",
        ]
        subprocess.run(args, check=True)

        if dl_subtitles:
            try:
                print("[*] Downloading subtitles...")
                resp = requests.get(subtitles_url, DEFAULT_HEADERS, timeout=10)
                if resp.status_code != 200:
                    print("[*] Subtitles are not available")
                    return

                with open(f"{output_dir}.vtt", mode="wb") as file:
                    file.write(resp.content)
            except Exception as ex:
                print(
                    f"[!] Exception thrown when attempting to download subtitles: {ex}"
                )
                raise
    except:
        print("[!] Failed merging streams")
        raise


def check_required_config_values() -> None:
    lets_go = True
    if not HMAC_SECRET:
        print("[*] HMAC_SECRET not set")
        lets_go = False
    if not AES_KEY:
        print("[*] AES_KEY not set")
        lets_go = False
    if not WVD_PATH:
        print("[*] WVD_PATH not set")
        lets_go = False
    if WVD_PATH and not os.path.exists(WVD_PATH):
        print("[*] WVD file does not exist")
    if not lets_go:
        sys.exit(1)


def create_argument_parser():
    parser = argparse.ArgumentParser(description="Channel 5 downloader.")
    parser.add_argument(
        "--download",
        "-d",
        help="Flag to download the episode",
        action="store_true",
    )
    parser.add_argument(
        "--subtitles",
        "-s",
        help="Flag to download subtitles",
        action="store_true",
    )
    parser.add_argument(
        "--url", "-u", help="The URL of the episode to download", required=True
    )
    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        sys.exit(1)
    return args


def main():
    check_required_config_values()
    parser = create_argument_parser()
    url = parser.url
    dl_video = parser.download
    dl_subtitles = parser.subtitles

    # Generate the episode URL
    episode_url = generate_episode_url(url)
    if episode_url is None:
        print("[!] Failed to get the episode URL")
        sys.exit(1)

    # Get the C5 content ID by parsing the reponse of the episode URL
    (
        content_id,
        season_number,
        episode_number,
        show_title,
        episode_title,
    ) = get_content_info(episode_url)
    if content_id is None:
        print("[!] Failed to get the content ID")
        sys.exit(1)

    # Generate the content URL from the C5 content ID
    content_url = generate_content_url(content_id)

    # Get the decrypted content response
    content_response = get_content_response(content_url)

    # Get the WVD key server URL, MPD and WebVTT from the first rendition
    lic_url, mpd_url, subtitles_url = get_first_rendition(content_response)

    # Get the MPD and extract the PSSH
    pssh = get_pssh_from_mpd(mpd_url)

    # Decrypt
    decryption_key = get_decryption_key(pssh, lic_url)

    if dl_video:
        delete_temp_files()
        output_title = download_streams(mpd_url, show_title, episode_title)
        decrypted_file_names = decrypt_streams(decryption_key, output_title)
        merge_streams(
            decrypted_file_names,
            show_title,
            season_number,
            episode_number,
            episode_title,
            subtitles_url,
            dl_subtitles,
        )
        delete_temp_files()

    print("[*] Done")


if __name__ == "__main__":
    main()
