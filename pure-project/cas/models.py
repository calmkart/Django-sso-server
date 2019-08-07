# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.


class start_up(models.Model):
    '''
    系统初始化标记，有记录则表示系统已经过初始化，无记录表示系统还未经过初始化
    '''
    startup_status = models.BooleanField()

    class Meta:
        verbose_name_plural = '系统初始化表'


class options(models.Model):
    '''
    系统设置,ldap地址及ldap管理员账号密码,cookie有效域和cookie有效期等设置
    '''
    ldap_url = models.CharField(max_length=50)
    base_dn = models.CharField(max_length=50)
    ldap_admin = models.CharField(max_length=50)
    ldap_pass = models.CharField(max_length=50)
    sys_admin = models.TextField(blank=True)
    cookie_domain = models.CharField(max_length=50, blank=True)
    cookie_timeout = models.IntegerField(default=36000)
    # 微信扫码登录相关配置


class weixin(models.Model):
    '''
    企业微信扫码登录相关配置
    '''
    appid = models.CharField(max_length=50, blank=True)
    agentid = models.CharField(max_length=50, blank=True)
    redirect_uri = models.CharField(max_length=150, blank=True)
    state = models.CharField(max_length=100, blank=True)
    # 企业微信corpid和corpsecret
    corpid = models.CharField(max_length=100, blank=True)
    corp_secret = models.CharField(max_length=100, blank=True)


class rsakeys(models.Model):
    '''
    rsa public key and rsa private key,用于cookie加解密以及ldap_pass加解密
    '''
    private_key = models.TextField()
    public_key = models.TextField()


class webs(models.Model):
    '''
    dashboard中需要导航的站点列表
    '''
    name = models.CharField(max_length=50)
    url = models.CharField(max_length=100)
