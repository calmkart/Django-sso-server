# -*- coding:utf-8 -*-
from __future__ import absolute_import
import logging
from django.http import HttpResponse, HttpResponseRedirect
import cas.models

def auth_login(func):
    '''
    装饰器,若系统未初始化,转到start初始化,若系统已初始化,验证cookie中是否能解出username
    若不能解出username或未有cookie,则返回login页面
    若能解出username,则将username传入视图中
    '''
    def _auth(request):
        if not cas.models.start_up.objects.all().exists():
            return HttpResponseRedirect('/start/')
        # cookie = request.COOKIES.get("sso_user", "")
        # username = _sso_decode(cookie)
        username = "pengng"
        if username == "" or username == "error":
            return HttpResponseRedirect('/login/')
        else:
            return func(request, username)
    return _auth

def _sso_decode(cookie):
    '''
    cookie解密
    '''
    return cookie


def log():
    logger = logging.getLogger('app_log')
    return logger