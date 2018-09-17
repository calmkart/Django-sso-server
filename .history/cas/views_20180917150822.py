# -*- coding:utf-8 -*-
import json
from django.shortcuts import render

# Create your views here.
# <view logic> return HttpResponse('result')

from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import render
from common import *
from models import *
from ldapop import MyLdap
from crypto import Aes, Rsa


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
                print type(ldap_url)
                print type(base_dn)
                print type(admin)
                print type(password)
                print type(sys_admin)
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
