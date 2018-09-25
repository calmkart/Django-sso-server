# -*- coding:utf-8 -*-
from __future__ import absolute_import
import logging
import time
from django.http import HttpResponse, HttpResponseRedirect
from cas.models import *
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
        username = sso_decode(cookie)
        if username == "" or username == "error":
            return HttpResponseRedirect('/login/')
        else:
            return func(request, username)
    return _auth


def sso_decode(cookie):
    '''
    cookie解密
    '''
    try:
        rsa = Rsa()
        aes = Aes()
        private_key = aes.decrypt(rsakeys.objects.all()[0].private_key)
        user_info = rsa.decrypt(private_key, cookie)
        # cookie超过有效期,返回error
        if int(time.time()) - int(float(user_info.split("|||||")[1])) > options.objects.all()[0].cookie_timeout:
            return "error"
        username = user_info.split("|||||")[0]
        return username
    except Exception as e:
        return 'error'


def log():
    logger = logging.getLogger('app_log')
    return logger


def sysadmin_login(func):
    '''
    装饰器,若未登录或未用sso系统管理员用户登录,返回403
    '''
    def _auth(request):
        if not start_up.objects.all().exists():
            return HttpResponse(status=403)
        cookie = request.COOKIES.get("sso_user", "")
        username = sso_decode(cookie)
        if username not in options.objects.all()[0].sys_admin.split(","):
            return HttpResponse(status=403)
        else:
            return func(request)
    return _auth
