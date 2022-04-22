# encoding: utf-8
"""
https://platform.openmmlab.com/docs/zh-CN/open-api/
"""
import hashlib
import os
import time
from collections import OrderedDict
from urllib.parse import urljoin

import magic
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
    response = requests.post(url, headers=Headers)
    if response.ok and response.json().get('msg', '') == 'ok':
        accessToken = response.json()['data']['accessToken'][len('Bearer'):].strip()
        return accessToken
    raise ValueError(f"Cannot get {response.url}")


def upload_file(accessToken, tag, files):
    """
    第三步：上传文件
    参考：https://platform.openmmlab.com/docs/zh-CN/open-api/steps/upload-file
    :return:
    """
    Host = r"https://platform.openmmlab.com"
    Path = r"/gw/upload-service/api/v1/uploadFile"
    Headers = dict(Authorization=accessToken)

    url = urljoin(Host, Path)

    key = "inference"
    params = dict(key=key, tag=tag)
    files_ = []
    for file in files:
        filename = os.path.basename(file)
        with open(file, 'rb') as f:
            body = f.read()
        content_type = magic.from_file(file, mime=True)
        files_.append(['file', (filename, body, content_type)])

    response = requests.post(url, params=params, headers=Headers, files=files_)
    if response.ok and response.json().get("msg", "") == "ok":
        return response
    return response

def classification_example(accessToken):
    """
    参考： https://platform.openmmlab.com/docs/zh-CN/open-api/guides/image-classification
    :return:
    """
    Host = "https://platform.openmmlab.com"
    Path = "/gw/model-inference/openapi/v1/classification"

    url = urljoin(Host, Path)
    Headers = dict(Authorization=accessToken)
    Body = dict(algorithm="Swin-Transformer",
                dataset="ImageNet",
                backend="PyTorch",
                resource="https://oss.openmmlab.com/web-demo/static/one.b7608e9b.jpg",
                resourceType="URL",
                requestType="SYNC"
                )
    response = requests.post(url, headers=Headers, json=Body)
    return response

if __name__ == '__main__':
    accessToken = get_access_token()
    ret = upload_file(accessToken=accessToken, tag="segmentation", files=[r'./data/fire.jpg'])
    print(ret)
    ret = classification_example(accessToken=accessToken)
    print(ret)