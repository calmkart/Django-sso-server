"""django_sso_server URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from cas import views as cas_views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^start/$', cas_views.start.as_view(), name="start"),
    url(r'^login/$|^$', cas_views.login.as_view(), name="login"),
    url(r'^dashboard/$', cas_views.dashboard.as_view(), name="dashboard"),
    url(r'^manage/$', cas_views.manage.as_view(), name="manage"),
    url(r'^changepass/', cas_views.change_pass.as_view(), name="changepass"),
    url(r'^logout/', cas_views.logout.as_view(), name="logout"),
    url(r'^api/', include('api.urls', namespace='api')),
    
]
