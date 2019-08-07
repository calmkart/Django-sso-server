# 基础服务运行镜像,不要改
FROM centos:centos7.6.1810

ARG VERSION="v0.0.1"

LABEL Description="django sso server docker image" Vendor="calmkart@calmkart.com" Version="${VERSION}"

RUN mkdir /root/.pip

COPY pip.conf /root/.pip/pip.conf
COPY CentOS-Base.repo /etc/yum.repos.d/
COPY ./pure-project /root/pure-project

WORKDIR /root/pure-project

RUN yum makecache \
    && yum install epel-release -y \
    && yum install -y wget \
    && yum install -y python2-pip.noarch \
    && yum install -y mysql-devel python-devel openldap-devel gcc \
    && pip install -r /root/pure-project/requirement.txt \
    && python manage.py migrate \
    && wget http://d.xiazaiziti.com/en_fonts/fonts/a/Arial.ttf

CMD sh -c "gunicorn -w4 -t 300 -b 0:8080 --access-logfile /root/pure-project/logs/access.log django_sso_server.wsgi"