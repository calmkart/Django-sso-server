# Django Sso Server
## 一个用户友好的Django单点登录系统
***
### 1 . 功能简介:

#### 总览
本系统为用于实现基于ldap验证或(和)企业微信扫码验证的单点登录系统

通过加解密cookie以及验证api的方式实现单点登录

#### 1 . 登录页
登录界面(可选择ldap登录或企业微信扫码登录)
![django-sso-server login page](http://www.calmkart.com/wp-content/uploads/2018/09/5C45207A-AF09-475D-ACD6-E732CFE1596D.png "django-sso-server login page")

#### 2 . 用户页
用于用户登录成功后的站点导航,其中后台页面不会显示给普通用户
![django-sso-server user page](http://www.calmkart.com/wp-content/uploads/2018/09/B9772DA0-588E-455A-B887-1C2EB471FE4B.jpg "django-sso-server user page")

#### 3 . 用户账户功能
用于修改ldap密码,以及登出

![django-sso-server user func](http://www.calmkart.com/wp-content/uploads/2018/09/B7925C24-0C92-4DF0-8B28-DB73159AF28E.jpg "django-sso-server user func")

#### 4.配置管理后台
用于sso系统配置管理以及添加导航站点
![django-sso-server options backend](http://www.calmkart.com/wp-content/uploads/2018/09/3E807D12-AE8B-4746-9B5A-20886A5533A3.png "django-sso-server options backend")

#### 5.企业微信扫码后台
用于配置企业微信扫码相关参数
![django-sso-server wx backend](http://www.calmkart.com/wp-content/uploads/2018/09/2C71241E-B1E1-4643-AE7F-5CA2D7E19E26.png "django-sso-server wx backend")

***
### 2 . 使用说明
#### 1 . 安装环境
<pre>
git clone https://github.com/calmkart/Django-sso-server.git
pip install -r requirement.txt
cd django-sso-server
创建数据库sso
python manage.py migrate
用django自带http服务器或者用gunicorn跑都可以
然后进行系统初始化
</pre>

#### 2 . 系统初始化
登录单点登录服务器,填写相关初始化信息

提交后后台会检验ldap相关信息是否正确,ldap管理员账户有错误将返回
![django-sso-server first start](http://www.calmkart.com/wp-content/uploads/2018/09/588F45F1-1F7F-4B68-9A28-733843791DB9.png "django-sso-server first start")

#### 3 . 配置
初始化成功后,使用初始化中配置的系统管理员ldap账号登录系统

在管理后台配置导航站点以及企业微信扫码登录相关参数

最后,可以在管理后台找到子站添加进sso系统的相关帮助
![django-sso-server help](http://www.calmkart.com/wp-content/uploads/2018/09/2D1A59D2-F7DF-4E7B-8593-B9635B81A70C.png "django-sso-server help")

*****

#### 4 . 子站鉴权api说明
<code>
/api/auth

子站用POST方法以json形式将{"sso_cookie":$sso_cookie}传给此api,

返回{"status":True, "msg":$username}则登录成功

返回{"status":False, "msg":$exception}则登录失败

</code>