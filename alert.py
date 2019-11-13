import datetime
import os
import time

from rs2wapy import RS2WebAdmin

from simplediscordwh import DiscordWebhook

WEBHOOK_URL = os.environ["WEBHOOK_URL"]
WA_USERNAME = os.environ["WA_USERNAME"]
WA_PASSWORD = os.environ["WA_PASSWORD"]
WA_URL = os.environ["WA_URL"]


def write_exception(e):
    try:
        e = f"{datetime.datetime.now().isoformat()}: {type(e)}: {e}\n"
        print(e)
        with open("errors.log", "a") as f:
            f.write(e)
            f.write("----------------\n")
    except Exception as e:
        print(e)


def connect(username, password, url) -> RS2WebAdmin:
    while True:
        try:
            return RS2WebAdmin(username, password, url)
        except Exception as e:
            print("retrying connection...")
            write_exception(e)


def main():
    wh = DiscordWebhook({
        "USER_AGENT": "TestBot 1.0",
        "WEBHOOK_URL": WEBHOOK_URL,
    })
    rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)

    while True:
        try:
            ranked = rs2wa.get_ranked_status()
            if not ranked.lower() == "ranked: yes":
                success = wh.post_chat_message("WARNING: Server un-ranked! <&563072608564936704>")
                if not success:
                    write_exception("error posting web hook message")
                time.sleep(30 * 30)
            else:
                print("still ranked...")
            time.sleep(15)
        except Exception as e:
            write_exception(e)
            rs2wa = connect(WA_USERNAME, WA_PASSWORD, WA_URL)


if __name__ == '__main__':
    main()
