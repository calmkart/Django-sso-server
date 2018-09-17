# -*- coding:utf-8 -*-
from __future__ import absolute_import

import json
from io import BytesIO

from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from cas.models import *
from common.captcha_handle import create_captcha
from common.common import *
from common.crypto import Aes, Rsa
from common.ldapop import MyLdap


class start(View):

    @method_decorator(csrf_exempt, name="post")
    def dispatch(self, *args, **kwargs):
        return super(start, self).dispatch(*args, **kwargs)

    def get(self, request):
        if start_up.objects.all().exists():
            return HttpResponseRedirect('/login/')
        else:
            return render(request, 'startup.html', {})

    def post(self, request):
        '''
        初始化sso系统,将ldap admin密码加密存放在数据库
        '''
        if start_up.objects.all().exists():
            return HttpResponseRedirect('/login/')
        else:
            try:
                data = json.loads(request.body)
                ldap_url = data["ldap_url"]
                base_dn = data["basedn"]
                admin = data["admin"]
                password = data["password"]
                sys_admin = data["sys_admin"]
                ldap_client = MyLdap(ldap_url, base_dn, admin, password)
                if ldap_client.status["status"]:
                    aes = Aes()
                    options.objects.create(ldap_url=ldap_url,
                                           base_dn=base_dn,
                                           ldap_admin=admin,
                                           ldap_pass=aes.encrypt(
                                               str(password)),
                                           sys_admin=sys_admin)
                    start_up.objects.create(startup_status=True)
                    return JsonResponse({"status": True, "msg": "系统初始化成功"})
                else:
                    return JsonResponse({"status": False, "msg": ldap_client.status["msg"]})
            except Exception as e:
                print e
                log().error(str(e))
                return JsonResponse({"status": False, "msg": str(e)})


class login(View):

    @method_decorator(csrf_exempt, name="post")
    @method_decorator(auth_login)
    def dispatch(self, *args, **kwargs):
        return super(login, self).dispatch(*args, **kwargs)

    def get(self, request, username):
        return render(request, 'login.html', {})

    def post(self, request, username):
        '''

        '''
        return JsonResponse({"status": True})


class get_captcha(View):

    def get(self, request):
        '''
        生成验证码图片和验证码code,返回验证码图片,并以<captcha:code>形式将验证码存放在session里
        '''
        try:
            f = BytesIO()
            img, code = create_captcha()
            request.session["captcha"] = code
            img.save(f,'PNG')
            return HttpResponse(f.getvalue())
        except Exception as e:
            log().error(str(e))                     
