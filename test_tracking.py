import os

import rs2wapy

from alert import connect
from simplediscordwh import DiscordWebhook

STEAM_WEB_API_KEY = os.environ["STEAM_WEB_API_KEY"]
DISCORD_WEBHOOK = os.environ["DISCORD_TEST_WH"]

WA_USERNAME = os.environ["WA_USERNAME"]
WA_PASSWORD = os.environ["WA_PASSWORD"]
WA_URL = os.environ["WA_URL"]


def main():
    print("***********************************************")
    print("rs2wapy.__version__:", rs2wapy.__version__)
    print("***********************************************")

    wh = DiscordWebhook({
        "USER_AGENT": "TestBot 1.0",
        "WEBHOOK_URL": DISCORD_WEBHOOK,
    })

    rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)
    tracking = rs2wa.get_tracked_players()
    for t in tracking:
        wh.post_chat_message(f"**{t.persona_name}** | {t}")


if __name__ == "__main__":
    main()
