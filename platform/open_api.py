# encoding: utf-8
"""
https://platform.openmmlab.com/docs/zh-CN/open-api/
"""
import hashlib
import time
from collections import OrderedDict
from urllib.parse import urljoin

import requests
import urllib3.util

from utils.constaint import AccessKey, SecretKey
from utils.open_utils import get_nonce, get_sign


def get_access_token():
    """
    第二步：获取令牌
    参考： https://platform.openmmlab.com/docs/zh-CN/open-api/steps/get-token
    :return:
    """
    ts = str(int(time.time()))
    nonce = get_nonce()
    accessKey = AccessKey
    secretKey = SecretKey

    uri = "/api/v1/openapi/auth"
    sign = get_sign(uri, ts, nonce, accessKey, secretKey)

    Host = r"https://platform.openmmlab.com"
    Path = r"/gw/user-service/api/v1/openapi/auth"

    Headers = dict(ts=ts, nonce=nonce, sign=sign, accessKey=accessKey)

    url = urljoin(Host, Path)
    ret = requests.post(url, headers=Headers)
    if ret.ok and ret.json().get('msg', '') == 'ok':
        accessToken = ret.json()['data']['accessToken'][len('Bearer'):].strip()
        return accessToken
    raise ValueError(f"Cannot get {ret.url}")


def

if __name__ == '__main__':
    ret = get_access_token()
    print(ret)