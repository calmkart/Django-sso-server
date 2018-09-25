# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import traceback
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

# Create your views here.


class get_captcha(View):

    def get(self, request):
        '''
        生成验证码图片和验证码code,返回验证码图片,并以<captcha:code>形式将验证码存放在session里
        '''
        try:
            f = BytesIO()
            img, code = create_captcha()
            request.session["captcha"] = code
            img.save(f, 'PNG')
            return HttpResponse(f.getvalue())
        except Exception:
            log().error(traceback.format_exc())


@method_decorator(csrf_exempt, name="dispatch")
class edit_options(View):
    '''
    修改options系统设置
    '''

    @method_decorator(sysadmin_login)
    def post(self, request):
        try:
            data = json.loads(request.body)
            ldap_host = data["ldap_host"]
            ldap_base_dn = data["ldap_base_dn"]
            ldap_admin = data["ldap_admin"]
            ldap_pass = data["ldap_pass"]
            sys_admin = data["sys_admin"]
            timeout = 10*3600 if data["timetout"]=='' else int(data["timetout"])
            domain = data["domain"]
            aes = Aes()
            options.objects.all().update(
                ldap_url=ldap_host,
                base_dn=ldap_base_dn,
                ldap_admin=ldap_admin,
                ldap_pass=aes.encrypt(str(ldap_pass)),
                sys_admin=sys_admin,
                cookie_domain=domain,
                cookie_timeout=int(timeout)
            )
            return JsonResponse({"status": True, "msg": "已成功修改系统设置"})
        except Exception as e:
            log().error(traceback.format_exc())
            return JsonResponse({"status": False, "msg": str(e)})


@method_decorator(csrf_exempt, name="dispatch")
class edit_web(View):
    '''
    修改站点导航列表
    '''

    @method_decorator(sysadmin_login)
    def post(self, request):
        try:
            data = json.loads(request.body)
            web_id = data["web_id"]
            web_name = data["web_name"]
            web_url = data["web_url"]
            # 若有传来web_id,则修改此站点详情
            if web_id:
                webs.objects.filter(pk=int(web_id)).update(
                    name=web_name,
                    url=web_url
                )
                return JsonResponse({"status": True, "msg": "已成功修改站点详情"})
            # 若无web_id,则新建站点
            else:
                webs.objects.create(
                    name=web_name,
                    url=web_url
                )
                return JsonResponse({"status": True, "msg": "已成功添加站点"})
        except Exception as e:
            log().error(traceback.format_exc())
            return JsonResponse({"status": False, "msg": str(e)})


@method_decorator(csrf_exempt, name="dispatch")
class del_web(View):
    '''
    删除导航站点
    '''

    @method_decorator(sysadmin_login)
    def post(self, request):
        try:
            data = json.loads(request.body)
            web_id = data["web_id"]
            webs.objects.get(pk=int(web_id)).delete()
            return JsonResponse({"status": True, "msg": "已成功删除站点"})
        except Exception as e:
            log().error(traceback.format_exc())
            return JsonResponse({"status": False, "msg": str(e)})


@method_decorator(csrf_exempt, name="dispatch")
class auth(View):
    '''
    用于下属站点登录鉴权和获取username
    '''

    def post(self, request):
        try:
            data = json.loads(request.body)
            sso_cookie = data["sso_cookie"]
            username = sso_decode(sso_cookie)
            if username == '' or username == 'error':
                return JsonResponse({"status":False, "msg":"error"})
            return JsonResponse({"status": True, "msg": username})
        except Exception as e:
            log().error(traceback.format_exc())
            return JsonResponse({"status": False, "msg": str(e)})
