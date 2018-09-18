# -*- coding:utf-8 -*-
from __future__ import absolute_import
import logging
from django.http import HttpResponse, HttpResponseRedirect
from  cas.models import *
from common.crypto import Aes, Rsa

def auth_login(func):
    '''
    装饰器,若系统未初始化,转到start初始化,若系统已初始化,验证cookie中是否能解出username
    若不能解出username或未有cookie,则返回login页面
    若能解出username,则将username传入视图中
    '''
    def _auth(request):
        if not start_up.objects.all().exists():
            return HttpResponseRedirect('/start/')
        cookie = request.COOKIES.get("sso_user", "")
        username = sso_decode(request, cookie)
        if username == "" or username == "error":
            return HttpResponseRedirect('/login/')
        else:
            return func(request, username)
    return _auth

def sso_decode(request, cookie):
    '''
    cookie解密
    '''
    try:
        rsa = Rsa()
        aes = Aes()
        private_key = aes.decrypt(rsakeys.objects.all()[0].private_key)
        user_info = rsa.decrypt(private_key, cookie)
        #cookie过期,与session中时间标记不符
        if user_info.split("|||||")[1] != request.session["time"]:
            return "error"
        username = user_info.split("|||||")[0]
        return username
    except Exception:
        return 'error'


def log():
    logger = logging.getLogger('app_log')
    return logger