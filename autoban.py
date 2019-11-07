import os
import time

from rs2wat import FTPCollector
from rs2wat import db

FTP_HOST = os.environ["FTP_HOST"]
FTP_PORT = os.environ["FTP_PORT"]
FTP_USERNAME = os.environ["FTP_USERNAME"]
FTP_PASSWORD = os.environ["FTP_PASSWORD"]

DATABASE_URL = os.environ["DATABASE_URL"]


def main():
    db.init_db(DATABASE_URL)

    while True:
        ftpc = FTPCollector(FTP_HOST, FTP_PORT, FTP_USERNAME, FTP_PASSWORD)
        new_m = ftpc.get_new_modifications("/81.19.210.136_7877/ROGame/Logs/Launch.log")
        print(f"got {len(new_m)} new modifications")
        time.sleep(1)


if __name__ == '__main__':
    main()
