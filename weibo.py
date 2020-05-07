import json
import random
import re
import time
import math

import os
import requests
import base64
from urllib import parse
from binascii import b2a_hex

import rsa

class Weibo():
    def __init__(self, username, password):
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36"
        }
        self.session.headers.update(self.headers)
        # 登录前获取加密参数
        self.prelogin = self.get_prelogin_params()


    # 生成 Nonce
    def makeNonce(self):
        x = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        nonce_str = ""
        for i in range(6):
            index_num = int(math.ceil(random.random() * 1000000) % len(x))
            nonce_str += x[index_num]
        return nonce_str

    # 处理 username
    def process_username(self):
        user = parse.quote(self.username)
        return base64.b64encode(user.encode())

    # 处理 password
    def process_password(self):
        passwd = "\t".join([str(self.prelogin["servertime"]), str(self.prelogin["nonce"])]) + "\n" + self.password
        return passwd

    # 获取加密参数
    def get_prelogin_params(self):
        url = "https://login.sina.com.cn/sso/prelogin.php"
        params = {
            "entry": "weibo",
            "callback": "sinaSSOController.preloginCallBack",
            "su": self.process_username(),
            "rsakt": "mod",
            'checkpin': '1',
            "client": "ssologin.js(v1.4.19)",
            "_": int(time.time() * 1000),
        }
        response = self.session.get(url, params=params, headers=self.headers, verify=False)
        re_mt = re.match(".*?({.*?}).*?\)", response.text)
        if re_mt:
            print("获取加密参数成功")
            return json.loads(re_mt.group(1))
        else:
            print("获取加密参数失败")
            raise response.text

    # 生成加密密码
    def get_encrypted_pwd(self):
        pubkey = rsa.PublicKey(int(self.prelogin["pubkey"], 16), int("10001", 16))
        return b2a_hex(rsa.encrypt(self.process_password().encode(), pubkey))

    def login(self):

        params = {
            "entry": "weibo",
            "gateway": "1",
            "from": "",
            "savestate": "0",
            "qrcode_flag": "false",
            "useticket": "1",
            "pagerefer": "https://login.sina.com.cn/crossdomain2.php?action=logout&r=https://weibo.com/logout.php?backurl=/",
            "vsnf": "1",
            "su": self.process_username(),
            "service": "miniblog",
            "servertime": self.prelogin["servertime"],
            "nonce": self.prelogin["nonce"],
            "pwencode": "rsa2",
            "rsakv": self.prelogin["rsakv"],
            "sp": self.get_encrypted_pwd(),
            "sr": "1920*1080",
            "encoding": "UTF-8",
            "prelt": "431",
            "url":"https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            "returntype": "TEXT"
        }

        url = "https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
        if self.prelogin["showpin"] == 1:
            # 需要输入验证码重新发送
            pin_code = self.get_cap(self.prelogin["pcid"])
            params["pcid"] = self.prelogin["pcid"]
            params["door"] = pin_code
            # login_response = self.session.post(url=url, data=params, headers=self.headers)
        login_response = self.session.post(url=url, data=params, headers=self.headers)
        if "4049" in login_response.text:
            self.login()
        else:
            print(login_response.text)


    def get_cap(self, pcid):
        # 需要输入验证码重新发送
        pimg_url = "https://login.sina.com.cn/cgi/pin.php?r=" + str(random.randint(0, 99999999)).zfill(8) + "&s=0&p=" + pcid
        img = self.session.get(pimg_url, headers=self.headers)
        filename = os.path.dirname(__file__) + "/weibo_pinimges/code.jpg"
        with open(filename, "wb") as f:
            f.write(img.content)
        # 验证码下载完毕
        pin_code = input("请输入验证码:")
        return pin_code


if __name__ == "__main__":
    user_info = {"username":"","password":""}
    weibo = Weibo(**user_info)
    weibo.login()