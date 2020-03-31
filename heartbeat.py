import os
import sys
import time

from logbook import Logger
from logbook import StreamHandler

from simplediscordwh import DiscordWebhook
from .alert import connect
from .alert import write_exception

WEBHOOK_URL = os.environ["WEBHOOK_URL_HEARTBEAT"]
WA_USERNAME = os.environ["WA_USERNAME"]
WA_PASSWORD = os.environ["WA_PASSWORD"]
WA_URL = os.environ["WA_URL"]

handler = StreamHandler(sys.stdout, level="INFO")
handler.format_string = (
    "[{record.time}] {record.level_name}: {record.module}: "
    "{record.func_name}: Process({record.process}): {record.message}")
logger = Logger(__name__)
logger.handlers.append(handler)

POLL_INTERVAL = 30


def main():
    wh = DiscordWebhook({
        "USER_AGENT": "TestBot 1.0",
        "WEBHOOK_URL": WEBHOOK_URL,
    })
    rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)

    while True:
        try:
            cg = rs2wa.get_current_game()
            num_players, _ = int(cg.info["Players"].split().strip())
            if num_players > 0:
                pings = [p.stats["Ping"] for p in rs2wa.get_players()]
                pings = [int(p.strip()) for p in pings]
                avg = sum(pings) / len(pings)
                min_ = min(pings)
                max_ = max(pings)
                msg = f"{num_players} players. Ping min={min_}, max={max_}, avg={avg}"
                wh.post_chat_message(msg)
        except Exception as e:
            write_exception(e)
            rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)

        time.sleep(POLL_INTERVAL - time.time() % POLL_INTERVAL)


if __name__ == "__main__":
    logger.info("{file} running as {name}", file=__file__, name=__name__)
    main()