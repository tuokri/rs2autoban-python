import os

from rs2wat import FTPCollector
from rs2wat import db

FTP_HOST = os.environ["FTP_HOST"]
FTP_PORT = os.environ["FTP_PORT"]
FTP_USERNAME = os.environ["FTP_USERNAME"]
FTP_PASSWORD = os.environ["FTP_PASSWORD"]

DATABASE_URL = os.environ["DATABASE_URL"]


def main():
    db.init_db(DATABASE_URL)
    ftpc = FTPCollector(FTP_HOST, FTP_PORT, FTP_USERNAME, FTP_PASSWORD)

    print(ftpc.get_new_modifications("Launch.log"))


if __name__ == '__main__':
    main()
