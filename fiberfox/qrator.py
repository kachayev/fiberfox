import js2py
from itertools import dropwhile
import random
import requests
import sys
import time

from main import humanbytes


QRATOR_COOKIE_NAME = "_pcl"


def cookie_challenge(html: str):
    lines = [line.strip() for line in html.splitlines(False) if line.strip()]
    lines = list(dropwhile(lambda l: not l.startswith("document.addEventListener"), lines))
    js = []
    for line in lines[1:]:
        if line.startswith("var config"):
            break
        js.append(line)
    js = "\n".join(js)
    return js2py.eval_js(js)


def qrator(target_url: str, num_requests: int, challenge: str):
    random.seed(time.time())
    total_traffic = 0
    for _ in range(10):
        with requests.session() as s:
            print("==> Sending initial request")
            with s.get(target_url) as resp:
                print(f"resp code={resp.status_code}, size={humanbytes(len(resp.content))}")
                for k, v in resp.cookies.items():
                    s.cookies.set(k, v)
                if resp.status_code == 429 and challenge == "":
                    challenge = cookie_challenge(resp.text)
                    print(f"⛰  cookie challenged: {challenge}")
                s.cookies.set(QRATOR_COOKIE_NAME, challenge)
            for ind in range(num_requests):
                time.sleep(random.random()*60+10)
                print(f"==> Signed request #{ind+1}")
                with s.get(target_url) as resp:
                    print(f"resp code={resp.status_code}, size={humanbytes(len(resp.content))}")
                    total_traffic += len(resp.content)
                    for k, v in resp.cookies.items():
                        s.cookies.set(k, v)
        challenge = ""
    print(f"🥃 traffic {humanbytes(total_traffic)}")


if __name__ == "__main__":
    qrator(sys.argv[1], int(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else "")

