# -*- coding:utf-8 -*-

from django.http import HttpResponse, HttpResponseRedirect
from models import *

def auth_login(func):
    def _auth(request):
        if not start_up.objects.all().exists():
            return HttpResponseRedirect('/start/')
        cookie = request.COOKIES.get("sso_user", "")
        username = _sso_decode(cookie)
        if username == "" or username == "error":
            return HttpResponseRedirect('/login/')
        else:
            return func(request, username)
    return _auth

def _sso_decode(cookie):
    return cookie
