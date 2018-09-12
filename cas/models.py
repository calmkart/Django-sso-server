#--*--coding:utf-8--*-
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
    系统设置,ldap地址及ldap管理员账号密码等设置
    '''
    ldap_url = models.CharField(max_length=50)
    organizations = models.CharField(max_length=50)
    ldap_admin = models.CharField(max_length=50)
    ldap_pass = models.CharField(max_length=50)

class rsakeys(models.Model):
    '''
    rsa public key and rsa private key,用于cookie加解密以及ldap_pass加解密
    '''
    private_key = models.TextField()
    public_key = models.TextField()
