from django.shortcuts import render
from .models import Overlay
from .onos_api import get_topology
from django.http import JsonResponse
import json

# Create your views here.
def home(request):
    overlays = Overlay.objects.all()
    return render(request, 'home.html', {'overlays': overlays})



def view_topology(request):
    topology = get_topology()
    devices = topology['devices']
    links = topology['links']
    
    return JsonResponse({
        'devices': devices,
        'links': links
    })