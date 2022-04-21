# encoding: utf-8
"""
为open_api服务
"""
import hashlib
import random
import string
from collections import OrderedDict


def get_nonce():
    """
    得到nouce值
    :return:
    """
    population = string.digits + string.ascii_letters
    k = 10
    ret = random.choices(population, k=k)
    ret = ''.join(ret)
    return ret


def get_sign(uri, ts, nonce, accessKey, secretKey):
    """
    返回根据签名规则生成的签名
    :param uri:
    :param ts:
    :param nonce:
    :param accessKey:
    :param secretKey:
    :return:
    """
    sign_rule = OrderedDict(uri=uri, ts=ts, nonce=nonce, accessKey=accessKey, secretKey=secretKey)
    sign_strs = [f"{k}={v}" for k, v in sign_rule.items()]
    sign_str = "&".join(sign_strs)
    sign = hashlib.sha256(sign_str.encode("utf-8")).hexdigest()
    return sign



if __name__ == '__main__':
    nounce = get_nonce()
    print(nounce)