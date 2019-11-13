import datetime
import logging
import os
import re
import subprocess
import sys
import time
from typing import List
from urllib.parse import urlparse

from logbook import Logger, StreamHandler
from rs2wapy import RS2WebAdmin
from rs2wat import FTPCollector
from rs2wat import db
from rs2wat.collectors import logger as rs2wat_collectors_logger

from simplediscordwh import DiscordWebhook

mh = StreamHandler(sys.stdout, level=logging.WARN, bubble=True)
logger = Logger(__name__)
logger.handlers.append(mh)
rs2wat_collectors_logger.handlers.append(mh)

FTP_HOST = os.environ["FTP_HOST"]
FTP_PORT = os.environ["FTP_PORT"]
FTP_USERNAME = os.environ["FTP_USERNAME"]
FTP_PASSWORD = os.environ["FTP_PASSWORD"]
WA_USERNAME = os.environ["WA_USERNAME"]
WA_PASSWORD = os.environ["WA_PASSWORD"]
WA_URL = os.environ["WA_URL"]
DATABASE_URL = os.environ["DATABASE_URL"]
WEBHOOK_URL = os.environ["WEBHOOK_URL"]
SERVER_IP = urlparse(WA_URL).netloc.split(":")[0]

LOG_IP_REGEX = (r"(.*\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)"
                r"{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*)")
PLAYER_NAME_REGEX = r".*PlayerName:\s(.*).*"
ADMIN_LOGIN = "ScriptLog: ===== Admin login:"
GRACE_PERIOD = 30


def get_suspicious_ips(ip_dict: dict) -> List[str]:
    susp = []
    for ip, name_list in ip_dict.items():
        if None in name_list:
            print(f"found suspicious IP: {ip}, name_list: {name_list}")
            susp.append(ip)
    return susp


def check_grace_periods(ips: List[str], timers: dict, wa: RS2WebAdmin,
                        dwh: DiscordWebhook) -> List[str]:
    for ip in ips:
        if ip not in timers:
            t = time.time()
            timers[ip] = t
            print(f"starting grace period timer for: {ip}: {t}")

    banned = []
    to_remove = []
    for ip, start_time in timers.items():
        if ip not in ips:
            print(f"adding no longer suspicious IP: {ip} to be removed")
            to_remove.append(ip)
        else:
            if time.time() > (start_time + GRACE_PERIOD):
                print(f"grace period expired for {ip}")
                policy = wa.get_access_policy()
                already_banned = False
                for p in policy:
                    if ip in p:
                        already_banned = True
                        print(f"{ip} already banned in WebAdmin")
                        break
                if not already_banned:
                    print(f"banning: {ip}")
                    wa.add_access_policy(ip, "DENY")
                    dwh.post_webhook({
                        "embeds": [{
                            "title": "Banning suspicious IP!",
                            "timestamp": f"{datetime.datetime.now().isoformat()}",
                            "description": f"An IP with no attached SteamID was found.",
                            "color": 0xFF283A,
                            "fields": [
                                {
                                    "name": "Banned IP",
                                    "value": f"[{ip}](https://whatismyipaddress.com/ip/{ip})",
                                    "inline?": False,
                                },
                            ],
                        }]
                    })
                    # print(f"adding banned IP to be removed: {ip}")
                    banned.append(ip)

    to_remove = list(set(to_remove + banned))
    banned = list(set(banned))
    for tr in to_remove:
        print(f"removing no longer suspicious IP: {tr}")
        timers.pop(tr)

    return banned


def main():
    db.init_db(DATABASE_URL)
    ftpc = FTPCollector(FTP_HOST, FTP_PORT, FTP_USERNAME, FTP_PASSWORD)
    wa = RS2WebAdmin(WA_USERNAME, WA_PASSWORD, WA_URL)
    dwh = DiscordWebhook({"USER_AGENT": "AutoBanBot 1.0", "WEBHOOK_URL": WEBHOOK_URL})
    ips = {}
    timers = {}

    while True:
        new_m = ftpc.get_new_modifications("/81.19.210.136_7877/ROGame/Logs/Launch.log")
        print(f"got {len(new_m)} new modifications")
        new_m = "\n".join(new_m)
        print(f"joined modification string length: {len(new_m)}")

        if new_m:
            it = re.finditer(LOG_IP_REGEX, new_m)
            count = 0
            for i in it:
                groups = i.groups()
                line = groups[0]

                if ADMIN_LOGIN.lower() in line.lower():
                    print(f"skipping admin login line: {line}")
                    continue

                ip = groups[1]
                if ip == SERVER_IP:
                    print(f"skipping server's own IP: {ip}")
                    continue

                name = None

                if ip not in ips:
                    print(f"found new IP: {ip}")
                    ips[ip] = {None}
                else:
                    try:
                        name = re.match(PLAYER_NAME_REGEX, line).groups()[0]
                    except (IndexError, AttributeError):
                        pass

                if name is not None:
                    try:
                        ips[ip].remove(None)
                    except KeyError:
                        pass
                    ips[ip].add(name)

                count += 1

            print(f"processed {count} matches")

        susp = get_suspicious_ips(ips)
        banned = check_grace_periods(susp, timers, wa, dwh)

        for b in banned:
            print(f"removing banned IP from IP dictionary: {b}")
            ips.pop(b)

        time.sleep(1)


if __name__ == '__main__':
    logger.warn("starting app")
    subprocess.Popen(["python", "alert.py"], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    main()
