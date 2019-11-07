import os
import re
import time
from typing import List

from rs2wapy import RS2WebAdmin
from rs2wat import FTPCollector
from rs2wat import db

FTP_HOST = os.environ["FTP_HOST"]
FTP_PORT = os.environ["FTP_PORT"]
FTP_USERNAME = os.environ["FTP_USERNAME"]
FTP_PASSWORD = os.environ["FTP_PASSWORD"]
WA_USERNAME = os.environ["WA_USERNAME"]
WA_PASSWORD = os.environ["WA_PASSWORD"]
WA_URL = os.environ["WA_URL"]
DATABASE_URL = os.environ["DATABASE_URL"]
WEBHOOK_URL = os.environ["WEBHOOK_URL"]

LOG_IP_REGEX = (r"(.*)\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)"
                r"{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*PlayerName:\s(.*)")
GRACE_PERIOD = 30


def get_suspicious_ips(ip_dict: dict) -> List[str]:
    susp = []
    for ip, name in ip_dict.items():
        if name is None:
            print(f"found suspicious ip: {ip}")
            susp.append(ip)
    return susp


def check_grace_periods(ips: List[str], timers: dict, wa: RS2WebAdmin):
    for ip in ips:
        if ip not in timers:
            t = time.time()
            timers[ip] = t
            print(f"starting grace period timer for: {ip}: {t}")

    for ip, start_time in timers.items():
        if ip not in ips:
            print(f"removing no longer suspicious ip: {ip}")
            timers.pop(ip)
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


def main():
    db.init_db(DATABASE_URL)
    ftpc = FTPCollector(FTP_HOST, FTP_PORT, FTP_USERNAME, FTP_PASSWORD)
    wa = RS2WebAdmin(WA_USERNAME, WA_PASSWORD, WA_URL)
    ips = {}
    timers = {}

    while True:
        new_m = ftpc.get_new_modifications("/81.19.210.136_7877/ROGame/Logs/Launch.log")
        print(f"got {len(new_m)} new modifications")
        new_m = "\n".join(new_m)
        print(f"joined modification string length: {len(new_m)}")

        it = re.finditer(LOG_IP_REGEX, new_m)
        for i in it:
            groups = i.groups()
            ip = groups[1]
            name = None
            try:
                name = groups[2]
            except IndexError:
                pass

            if ip not in ips:
                ips[ip] = set()

            if name:
                try:
                    ips[ip].remove(None)
                except KeyError:
                    pass

            ips[ip].add(name)

        susp = get_suspicious_ips(ips)
        check_grace_periods(susp, timers, wa)

        time.sleep(1)


if __name__ == '__main__':
    main()
