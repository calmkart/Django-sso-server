import json
from django.shortcuts import render

# Create your views here.
# <view logic> return HttpResponse('result')

from django.http import HttpResponse, HttpResponseRedirect
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from common import *
from models import *

class start(View):
    def get(self, request):
        if start_up.objects.all().exists():
            return HttpResponseRedirect('/login/')
        else:
            return render(request, 'startup.html', {})
