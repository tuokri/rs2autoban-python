import datetime
import os
import subprocess
import sys
import time

from logbook import Logger
from logbook import StreamHandler
from rs2wapy import RS2WebAdmin

from simplediscordwh import DiscordWebhook

WEBHOOK_URL = os.environ["WEBHOOK_URL"]
WA_USERNAME = os.environ["WA_USERNAME"]
WA_PASSWORD = os.environ["WA_PASSWORD"]
WA_URL = os.environ["WA_URL"]

handler = StreamHandler(sys.stdout, level="INFO")
handler.format_string = (
    "[{record.time}] {record.level_name}: {record.module}: "
    "{record.func_name}: Process({record.process}): {record.message}")
logger = Logger(__name__)
logger.handlers.append(handler)


def write_exception(e):
    try:
        e = f"{datetime.datetime.now().isoformat()}: {type(e)}: {e}\n"
        print(e)
        with open("errors.log", "a") as f:
            f.write(e)
            f.write("----------------\n")
    except Exception as e:
        logger.error(e)


def connect(username, password, url) -> RS2WebAdmin:
    while True:
        try:
            return RS2WebAdmin(username, password, url)
        except Exception as e:
            logger.info("retrying connection...")
            write_exception(e)


def main():
    wh = DiscordWebhook({
        "USER_AGENT": "TestBot 1.0",
        "WEBHOOK_URL": WEBHOOK_URL,
    })
    rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)

    while True:
        try:
            ranked = rs2wa.get_current_game().info["Ranked"]
            if not ranked:
                success = wh.post_chat_message(
                    "WARNING: Server unranked! <@&563072608564936704> <@&548614059768020993> "
                    "<@&643482540346179584>")
                if not success:
                    write_exception("error posting web hook message")
                time.sleep(30 * 30)
            else:
                logger.info("still ranked...")
            time.sleep(15)
        except Exception as e:
            write_exception(e)
            rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)


if __name__ == "__main__":
    logger.info("{file} running as {name}", file=__file__, name=__name__)
    main()
    subprocess.Popen("heartbeat.py")
