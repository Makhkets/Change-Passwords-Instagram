import psutil
from licensing.methods import Key, Helpers
from licensing.models import *
from base64 import b64encode
from collections import OrderedDict
from wmi import WMI
import json
import wmi
from configparser import ConfigParser
from logging import log
import re
import shutil
import requests
from loguru import logger
from datetime import datetime
import time
import fake_useragent
from requests.api import head
import argparse
import sys
import os
sys.path.append(os.path.join(sys.path[0], "../"))
from instabot import Bot  # noqa: E402

print(f"""
\t\t\t\t\t           _      _____ ________      __
\t\t\t\t\t     /\   | |    |_   _|  ____\ \    / /
\t\t\t\t\t    /  \  | |      | | | |__   \ \  / / 
\t\t\t\t\t   / /\ \ | |      | | |  __|   \ \/ /  
\t\t\t\t\t  / ____ \| |____ _| |_| |____   \  /   
\t\t\t\t\t /_/    \_\______|_____|______|   \/     
\t\t\t\t\t [+] Создатель: Алиев
""")

file = "config.ini"
config = ConfigParser()
config.read(file, encoding="utf-8")

loginCFG = config["settings"]["login"]
passwordCFG = config["settings"]["password"]
textspm = config["settings"]["text"]
linkspm = config["settings"]["link"]
username_sub = config['settings']['username_subscribe']

chat_id = config["telegram"]["chat_id"]
BOT_TOKEN = config["telegram"]["bot_token"]

key1 = config['working']['key']


parser = argparse.ArgumentParser(add_help=True)
parser.add_argument("-u", type=str, help=f"{loginCFG}")
parser.add_argument("-p", type=str, help=f"{passwordCFG}")
args = parser.parse_args()

s = requests.Session()
link = "https://www.instagram.com/accounts/login/"
login_url = "https://www.instagram.com/accounts/login/ajax/"
time1 = int(datetime.now().timestamp())
user = fake_useragent.UserAgent().random

vv = open('valid.txt', 'a', encoding='utf=8')
vv.write('Ищу аккаунты\n')


def auth_script():
    RSAPubKey = "<RSAKeyValue><Modulus>qh0nzFTXrXDte6pnsM+2UxFPaGBA/ZhEvZaWBL++A9FXouqu4HDtq7v0HsDQit9bvDyLt0k1kRRtfLCmtydAAFAiUEKBYDU+4Xs7ryornBabQ1mgEfIP7Ogv2YSZ/3UJy+fmot52JWzeT2PWqUxmBfjAIaVIu7pxA5/nnLmAdYoA1htXjtk6pnPjkUZAvrtonJnQibHQ0ENKBKusZnyjlQprsgkhpXWn0BUiKJjLcaOAwWDZkdj5ieilzDpmNFZnfSes9jM0jVCKefRv9cBsRXdVT1iqNE59pG4M5Q6r0hxTHRArSpgNjuQmIIH++GV47LtEXKHpRRVsEU4zRNDQ2Q==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
    access = "WyI3MjY0NzUzIiwiK1ZKYTVhOG9RRGtwaWdsU3NsaThEb2Q1K1dkL0llUm5JcjRJRnUwciJd"

    """protection"""
    for proc in psutil.process_iter():
        name = proc.name()
        if name == "HTTPDebuggerUI.exe":
            # print("Do not try that.")
            time.sleep(2)
            # exit(0)

    key = str(key1)
    result = Key.activate(
        token=access,
        rsa_pub_key=RSAPubKey,
        product_id='13215',
        key=key1,
        machine_code=Helpers.GetMachineCode()
    )

    if result[0] == None or not Helpers.IsOnRightMachine(result[0]):
        # ошибка и ее причина
        logger.info(f"Ключ не работает: {result[1]}")
        logger.info("Купить ключ у @decode_mi")
        sys.exit()
    else:
        # Если ключ правильный:
        logger.info("Ключ верный!")
        # тут можно написать то, что будет происходить если ключ верный


def get_username():
    sys.path.append(os.path.join(sys.path[0], "../"))
    from instabot import Bot  # noqa: E402

    bot = Bot()
    bot.login(username=args.u, password=args.p)
    usernames = []
    id_users = bot.get_user_following('flight_muz')  # Список подписок
    print(id_users)
    for id_user in id_users:
        usernames.append(bot.get_username_from_user_id(id_user))
    return usernames


def follow_user_following(usrname):
    sys.path.append(os.path.join(sys.path[0], "../"))
    from instabot import Bot  # noqa: E402

    bot = Bot()
    bot.login(username=args.u, password=args.p)

    user_following = bot.get_user_following(usrname)  # Список подписок

    for idusr in user_following:
        bot.follow(idusr)


def auth(login, password):
    payload = {
        "username": login,
        "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{time1}:{password}",
        "queryParams": {},
        "optIntoOneTap": "false",
    }

    r = s.get(link)
    csrf = re.findall(r"csrf_token\":\"(.*?)\"", r.text)[0]
    r = s.post(
        login_url,
        data=payload,
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
            "x-requested-with": "XMLHttpRequest",
            "referer": "https://www.instagram.com/accounts/login/",
            "x-csrftoken": csrf,
        },
    )
    print(r.text)

    if '{"user":false,"authenticated":false' in r.text:
        logger.error('Невалид')
    else:
        logger.success(f'Валидный аккаунт')


def parseCRFToken():
    r = s.get("https://www.instagram.com/")

    crf_token_parse = r.text.split('window._sharedData = {"config":{"csrf_token":"')[
        1
    ].split('",')[0]

    return crf_token_parse


def comment(link, message_spam):
    r = s.get(link)
    time.sleep(1)
    id_img = r.text.split('"GraphVideo","id":"')[1].split('",')[0]
    crf_token_parse = r.text.split('window._sharedData = {"config":{"csrf_token":"')[
        1
    ].split('",')[0]

    while True:
        all_users_name = ['mill_mus', 'kurskworkoutslava', 'petruhanchik', 'latyshev_09', 'cristaly.text', '__k4au__', 'ditchevskie', 'imperia_latyshev_sirotina', 'fortune.finally',
                          'dream_muzz_', 'jungle.day', 'limferia', '78nochey', 'loover.gr', '_infractum', 'ketoo.13', 'sadness.sound', 'podkayfom.myz',
                          'limma_group', '__alyona__kalugina__', 'majorkahub', '_cars_movie_', 'tatyana_kh08', 'erokhinvova', 'gogaxs', 'polusladkie.gr', 'pushka.mus',
                          'org.crime.gr.jacksonstreetboys', '_mwrti_', '1stinbastogne', 'brokenskye', 'udovolstvie.ff', 'victorissas_s', '_seveone',
                          'axyeno.mus', 'pereverzevgrigorii']
        for users_name in all_users_name:
            data3213 = {
                "comment_text": f'{message_spam} + @{users_name}', "replied_to_comment_id": ""}
            time.sleep(3)
            s.post(
                f"https://www.instagram.com/web/comments/{id_img}/add/",
                data=data3213,
                headers={
                    "user-agent": user,
                    "x-requested-with": "XMLHttpRequest",
                    "referer": "https://www.instagram.com",
                    "x-csrftoken": crf_token_parse,
                },
            ).json
            time.sleep(3)
            logger.debug(id_img)
            logger.success(crf_token_parse)


def parseMyProfile():
    req = s.get("https://www.instagram.com/").text

    MyNickname = req.split('"username":"')[1].split('"')[0]
    print(f"Your nickname: {MyNickname}")

    MyProfile = s.get(f'https://www.instagram.com/{MyNickname}/').text
    followers = MyProfile.split('<meta property="og:description" content="')[
        1].split('Followers')[0].replace(' ', '')
    following = MyProfile.split('Followers, ')[1].split(
        'Following,')[0].replace(' ', '')
    posts = MyProfile.split('Following, ')[1].split('Posts')[
        0].replace(' ', '')

    print(
        f'Публикаций: {posts} | Подписчиков: {followers} | Подписок: {following}')
    return MyNickname


def checker():
    with open('accounts.txt') as a:
        accounts = a.readlines()
    count = len(accounts)
    logger.success(str(count) + ' Аккаунтов найдено')
    final_list = []
    for i in accounts:
        final_list.append(i.strip())
    logger.success(final_list)

    for account in final_list:

        login = account.split(':')[0]
        password = account.split(':')[1]
        logger.info(f'Проверяю аккаунт: {login}:{password}')
        try:
            time.sleep(2)
            auth(login, password)
            parseMyProfile()
            vv.write(f'{login}:{password}')

        except Exception as ex:
            logger.debug(ex)
            logger.error('Невалид')


def unfollowing():
    while True:
        bot = Bot()
        t3 = bot.login(username=args.u, password=args.p)
        t4 = bot.unfollow_everyone()


def main():
    # print(get_username())
    try:
        shutil.rmtree('config')
    except:
        pass

    # auth_script() Защита скрипта, при включении этого пункта будет требоваться авторизация в скрипте.
    work_mode = input('1 - Отписка от всех аккаунтов\n2 - Спам комментариями\n3 - Чекер аккаунтов\n4 - Подписаться на всех людей которые находятся в подписках у человека\nКакую функцию хотите включить: ')
    if work_mode == '1':
        unfollowing()
    elif work_mode == '2':
        auth(loginCFG, passwordCFG)
        comment(linkspm, textspm)

    elif work_mode == '3':
        auth(loginCFG, passwordCFG)
        checker()

    elif work_mode == '4':
        follow_user_following(username_sub)


if __name__ == "__main__":
    main()
