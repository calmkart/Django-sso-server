# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
import time
import traceback

from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from cas.models import *
from common.common import *
from common.crypto import Aes, Rsa
from common.ldapop import MyLdap


@method_decorator(csrf_exempt, name="dispatch")
class start(View):

    def get(self, request):
        if start_up.objects.all().exists():
            return HttpResponseRedirect('/login/')
        else:
            return render(request, 'startup.html', {})

    def post(self, request):
        '''
        初始化sso系统,将ldap admin密码加密存放在数据库
        生成rsa加解密密钥,经过aes加密后存放在数据库
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
                timeout = 10*3600 if data["timetout"]=='' else int(data["timetout"])*3600
                domain = data["domain"]
                # 验证ldap地址及管理员账号密码是否有效
                ldap_client = MyLdap(ldap_url, base_dn, admin, password)
                if ldap_client.status["status"]:
                    # 将ldap地址及管理员账号aes加密存放在数据库中
                    aes = Aes()
                    options.objects.create(
                        ldap_url=ldap_url,
                        base_dn=base_dn,
                        ldap_admin=admin,
                        ldap_pass=aes.encrypt(str(password)),
                        sys_admin=sys_admin,
                        cookie_domain=domain,
                        cookie_timeout=int(timeout),
                    )
                    start_up.objects.create(startup_status=True)
                    # 生成rsa公私钥,aes加密存放在数据库中
                    rsa = Rsa()
                    (pri, pub) = rsa.gen_rsa_keys()
                    rsakeys.objects.create(
                        private_key=aes.encrypt(pri),
                        public_key=pub
                    )
                    return JsonResponse({"status": True, "msg": "系统初始化成功"})
                else:
                    return JsonResponse({"status": False, "msg": ldap_client.status["msg"]})
            except Exception as e:
                # 有错误则删除生成的初始化信息
                options.objects.all().delete()
                start_up.objects.all().delete()
                rsakeys.objects.all().delete()
                log().error(traceback.format_exc())
                return JsonResponse({"status": False, "msg": str(e)})


@method_decorator(csrf_exempt, name="dispatch")
class login(View):

    def get(self, request):
        if not start_up.objects.all().exists():
            return HttpResponseRedirect('/start/')
        cookie = request.COOKIES.get("sso_user", "")
        username = sso_decode(cookie)
        if username == '' or username == 'error':
            return render(request, 'login.html')
        else:
            return HttpResponseRedirect('/dashboard/')

    def post(self, request):
        '''
        登录验证ldap账号密码以及验证码,成功则写cookie
        '''
        try:
            data = json.loads(request.body)
            ldap_username = data["ldap_username"]
            password = data["password"]
            captcha = data["captcha"]
            # 比较验证码
            if request.session["captcha"].lower() != captcha.lower():
                return JsonResponse({"status": False, "msg": "验证码错误!"})
            # 验证ldap账号密码
            aes = Aes()
            opt = options.objects.all()[0]
            ldap_client = MyLdap(opt.ldap_url,
                                 opt.base_dn,
                                 opt.ldap_admin,
                                 aes.decrypt(opt.ldap_pass))
            if not ldap_client.ldap_get(uid=ldap_username, passwd=password):
                return JsonResponse({"status": False, "msg": "账号或密码输入错误!"})
            # 写cookie,设置cookie_domain
            rsa = Rsa()
            now = time.time()
            public_key = rsakeys.objects.all()[0].public_key
            user_info = "{0}|||||{1}".format(ldap_username, now)
            response = JsonResponse({"status": True})
            response.set_cookie('sso_user', rsa.crypto(
                public_key, user_info), domain=options.objects.all()[0].cookie_domain)
            # request.session.set_expiry(30*60)
            return response
        except Exception as e:
            log().error(traceback.format_exc())
            return JsonResponse({"status": False, "msg": str(e)})


class dashboard(View):

    @method_decorator(auth_login)
    def get(self, request, username):
        # 判断是否是管理员
        if username in options.objects.all()[0].sys_admin.split(","):
            admin_flag = 1
        return render(request, 'dashboard.html',
                      {
                          "displayName": username,
                          "admin_flag": admin_flag,
                          # 载入所有需要导航的站点
                          "systems": webs.objects.all()
                      }
                      )


@method_decorator(csrf_exempt, name="dispatch")
class manage(View):

    @method_decorator(auth_login)
    def get(self, request, username):
        # 判断是否是管理员
        if username not in options.objects.all()[0].sys_admin.split(","):
            return HttpResponseRedirect('/dashboard/')
        aes = Aes()
        ldap_pass = aes.decrypt(options.objects.all()[0].ldap_pass)
        return render(request, 'manage.html',
                      {
                          "displayName": username,
                          "admin_flag": 1,
                          "options": options.objects.all()[0],
                          "ldap_pass": ldap_pass,
                          "webs": webs.objects.all()
                      }
                      )


class logout(View):
    '''
    退出登录
    '''

    @method_decorator(auth_login)
    def get(self, request, username):
        response = HttpResponseRedirect('/login/')
        response.delete_cookie('sso_user')
        return response


@method_decorator(csrf_exempt, name="dispatch")
class change_pass(View):
    '''
    退出登录
    '''

    @method_decorator(auth_login)
    def post(self, request, username):
        try:
            data = json.loads(request.body)
            oldpass = data["oldpass"]
            newpass = data["newpass"]
            opt = options.objects.all()[0]
            aes = Aes()
            ldap_client = MyLdap(opt.ldap_url,
                                 opt.base_dn,
                                 opt.ldap_admin,
                                 aes.decrypt(opt.ldap_pass))
            if not ldap_client.ldap_get(uid=username, passwd=oldpass):
                return JsonResponse({"status":False, "msg":"密码输入错误"})
            uppass_res = ldap_client.cnupdatepass(cn=username, passwd=newpass)
            if uppass_res["status"] == True:
                return JsonResponse({"status":True})
            else:
                return JsonResponse({"status":False, "msg":uppass_res["msg"]})
        except Exception as e:
            log().error(traceback.format_exc())
            return JsonResponse({"status":False, "msg":str(e)})
