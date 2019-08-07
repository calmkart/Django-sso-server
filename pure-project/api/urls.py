from django.conf.urls import url

from api import views as api_views

urlpatterns = [
    url(r'^get_captcha/$', api_views.get_captcha.as_view(), name='get_captcha'),
    url(r'^edit_options/$', api_views.edit_options.as_view(), name="edit_options"),
    url(r'^edit_web/$', api_views.edit_web.as_view(), name="edit_web"),
    url(r'^del_web/$', api_views.del_web.as_view(), name="del_web"),
    url(r'^auth/$', api_views.auth.as_view(), name="auth"),
]
