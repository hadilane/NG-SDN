
from .models import Overlay
from .onos_api import get_topology
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
import json
from django.contrib import messages
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from django.utils.timezone import now
import logging
from .decorators import role_required

# Create your views here.

def home(request):
    overlays = Overlay.objects.filter(user=request.user)
    return render(request, 'home.html', {'overlays': overlays})



def view_topology(request):
    topology = get_topology()
    devices = topology['devices']
    links = topology['links']
    
    return JsonResponse({
        'devices': devices,
        'links': links
    })




@login_required
@role_required('admin')
def dashboard(request):
    return render(request, 'Adminpages/dashboard.html')



# Registration

logger = logging.getLogger(__name__)  # for auditing

@login_required
@role_required('admin')
def register_view(request):
    """ Handle user registration with role assignment """
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, 'Account created. Please login.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'Authentication/register.html', {'form': form})


# Login
def login_view(request):
    """ Authenticate user and redirect based on role """
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            logger.info(f"User {user.username} logged in at {now()} with role {user.role}")
            if user.role == 'admin':
                return redirect('dashboard')
            else:
                return redirect('home')
    else:
        form = CustomAuthenticationForm()
    return render(request, 'Authentication/login.html', {'form': form})

# Logout
def logout_view(request):
    """ Log the user out and clean up session """
    logger.info(f"User {request.user.username} logged out at {now()}")
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')

