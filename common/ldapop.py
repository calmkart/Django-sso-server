# -*- coding:utf-8 -*-
from __future__ import absolute_import

import binascii
import hashlib
from base64 import b64encode

import ldap
import ldap.modlist as modlist

from common.common import log


class MyLdap():
     
    def __init__(self,ldap_host=None,base_dn=None,user=None,password=None):
        self.base_dn = base_dn
        self.ldap_host = ldap_host
        self.user = user
        self.password = password
        try:
            self.ldapconn = ldap.initialize(ldap_host)
            self.ldapconn.simple_bind(user,password)
        except ldap.LDAPError,e:
            log().error(str(e))
            print e

    @property
    def status(self):
        '''
        验证初始化ldap账号密码,以及ldap地址是否正确
        '''
        ldap_client = ldap.initialize(self.ldap_host)
        try:
            ldap_client.simple_bind_s(self.user, self.password)
            ldap_client.unbind_s()
            return {"status":True}
        except Exception as e:
            log().error(str(e))
            return {"status":False, "msg":"ldap初始化管理员账号密码或ldap地址有误,详情:{0}".format(str(e))}

    def _ldap_search_dn(self,uid=None):
        obj = self.ldapconn
        obj.protocal_version = ldap.VERSION3
        searchScope = ldap.SCOPE_SUBTREE
        retrieveAttributes = None 
        searchFilter = "cn=" + uid
        
        try:
            ldap_result_id = obj.search(self.base_dn, searchScope, searchFilter, retrieveAttributes)
            result_type, result_data = obj.result(ldap_result_id, 0)
            if result_type == ldap.RES_SEARCH_ENTRY:
                return result_data[0][0]
            else:
                return None
        except ldap.LDAPError, e:
            log().error(str(e))

    def ldap_get_user(self,uid=None):
        '''
        获取ldap用户详情,失败返None
        '''
        obj = self.ldapconn
        obj.protocal_version = ldap.VERSION3
        searchScope = ldap.SCOPE_SUBTREE
        retrieveAttributes = None 
        searchFilter = "cn=" + uid
        try:
            ldap_result_id = obj.search(self.base_dn, searchScope, searchFilter, retrieveAttributes)
            result_type, result_data = obj.result(ldap_result_id, 0)
            if result_type == ldap.RES_SEARCH_ENTRY:
                username = result_data[0][1]['cn'][0]
                mail = result_data[0][1]['mail'][0]
                displayName = result_data[0][1]['displayName'][0]
                sn = result_data[0][1]['sn'][0]
                result = {'username':username,'mail':mail,'displayName':displayName, 'sn':sn}
                return result
            else:
                return None
        except ldap.LDAPError, e:
            log().error(str(e))
    
    def ldap_get(self,uid=None,passwd=None):
        '''
        验证ldap账号密码,成功返True,失败返False
        '''
        target_cn = self._ldap_search_dn(uid)
        if not target_cn:
            return False   
        try:
            client = ldap.initialize(self.ldap_host)
            client.simple_bind_s(target_cn,passwd)
            client.unbind_s()
            return True
        except ldap.LDAPError,e:
            log().error(str(e))
            return False

    
    def cnupdatepass(self, cn, passwd):
        '''
        更改ldap密码,成功返True,失败返error
        '''
        dn='cn={0},{1}'.format(cn, self.base_dn)
        try:
            result=self.ldapconn.search_s(dn, ldap.SCOPE_SUBTREE, 'cn=%s' % cn)
            oldpass=result[0][1]['userPassword']
            oldwifipass=result[0][1]['sambaNTPassword']
            newpass='{MD5}' + b64encode(hashlib.md5(passwd).digest())
            wifipass=binascii.hexlify(hashlib.new('md4', passwd.encode('utf-16le')).digest())
            old={'userPassword':oldpass,'sambaNTPassword': oldwifipass}
            new={"sambaNTPassword": [wifipass],"userPassword":[newpass]}
            mlist = modlist.modifyModlist(old, new)
            self.ldapconn.modify_s(dn, mlist)
            return {"status":True}
        except ldap.LDAPError as e:
            log().error(str(e))
            return {"status":False, "msg":"ldap更改密码错误,详情: {0}".format(str(e))}
