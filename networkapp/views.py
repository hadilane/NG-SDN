
from .models import Overlay
from .onos_api import get_topology
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
import json
from django.contrib import messages
from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordResetForm
from django.utils.timezone import now
import logging
from .decorators import role_required
from django.contrib.auth.views import PasswordResetView
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.views.generic import FormView
from django.conf import settings
from django.urls import reverse_lazy
from .models import CustomUser
from django.shortcuts import render, redirect, get_object_or_404
from .models import CustomUser
from django.contrib.auth.decorators import login_required
from .decorators import role_required
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from .forms import OverlayForm, OverlayUploadForm
from django.views.decorators.http import require_http_methods





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
    """ Authenticate user and handle 'remember me' option """
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            # Handle 'Remember Me'
            if not request.POST.get('remember_me'):
                request.session.set_expiry(0)  # Session expires on browser close
            else:
                request.session.set_expiry(1209600)  # 2 weeks

            if user.role == 'admin':
                return redirect('dashboard')
            else:
                return redirect('overlays_list')
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

# Password Reset
class CustomPasswordResetView(FormView):
    template_name = 'Authentication/forgot-password.html'
    form_class = CustomPasswordResetForm
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        users = CustomUser.objects.filter(email=email)

        for user in users:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            context = {
                'user': user,
                'domain': '127.0.0.1:8000',  # 🔁 Replace with your IP/domain in prod
                'uid': uid,
                'token': token,
                'protocol': 'http',
            }

            # Render all parts of the email
            subject = render_to_string('Authentication/password_reset_subject.txt', context).strip()
            html_content = render_to_string('Authentication/password_reset_email.html', context)

            msg = EmailMultiAlternatives(
                subject=subject,
                body=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()

        return super().form_valid(form)
    



@login_required
@role_required('admin')
def clients_list(request):
    clients = CustomUser.objects.filter(role='client')

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST, request.FILES)
        if form.is_valid():
            client = form.save(commit=False)
            client.username = client.email
            client.role = 'client'
            random_password = get_random_string(length=10)
            client.set_password(random_password)
  
            client.save()
            messages.success(request, 'Client added successfully.')
            return redirect('clients')
        else:
            active_tab = 'addnew'  # If form is invalid, show add tab
    else:
        form = CustomUserCreationForm()
        active_tab = 'list'

    return render(request, 'Adminpages/project-clients.html', {
        'clients': clients,
        'form': form,
        'active_tab': active_tab
    })




@login_required
@role_required('admin')
def delete_client(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id, role='client')
    user.delete()
    return redirect('clients')

@login_required
@role_required('admin')
def toggle_client_status(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id, role='client')
    user.is_active = not user.is_active
    user.save()
    return redirect('clients')


# Overlay section ----------------------------------

@login_required
@role_required('client')
def overlays_list(request):
    overlays = Overlay.objects.filter(user=request.user)
    return render(request, 'OverlayPages/overlays-list.html', {'overlays': overlays})




import json

@login_required
@role_required('client')
def overlay_detail(request, overlay_id):
    overlay = get_object_or_404(Overlay, id=overlay_id, user=request.user)

    # --- DEBUG: Print the raw topology ---
    print("Raw topology:", type(overlay.topology), overlay.topology)

    # Force to dict
    if isinstance(overlay.topology, str):
        try:
            topology_data = json.loads(overlay.topology)
        except json.JSONDecodeError as e:
            print("JSON Error:", e)
            topology_data = {}
    else:
        topology_data = overlay.topology

    print("Final topology_data:", type(topology_data), topology_data)  # 👈 Must be dict

    return render(request, 'OverlayPages/overlay-detail.html', {
        'overlay': overlay,
        'topology_json': topology_data,
    })





@login_required
@role_required('client')
def add_overlay(request):
    if request.method == 'POST':
        if 'submit_form' in request.POST:
            form = OverlayForm(request.POST)
            upload_form = OverlayUploadForm()  # Empty, skip validation
            if form.is_valid():
                overlay = form.save(commit=False)
                overlay.user = request.user
                overlay.switches = form.cleaned_data.get('switches', {}) or {}
                overlay.topology = form.cleaned_data.get('topology', {}) or {}
                overlay.save()
                messages.success(request, 'Overlay added successfully.')
                return redirect('overlays_list')
        elif 'submit_json' in request.POST:
            form = OverlayForm()  # Empty, skip validation
            upload_form = OverlayUploadForm(request.POST, request.FILES)
            if upload_form.is_valid():
                json_file = upload_form.cleaned_data['json_file']
                try:
                    data = json.load(json_file)
                    name = data.get('name', 'Unnamed Overlay')
                    status = data.get('status', 'Unknown')
                    overlay = Overlay.objects.create(
                        user=request.user,
                        name=name,
                        status=status,
                        switches=data.get('switches', {}),
                        topology=data.get('topology', {})
                    )
                    messages.success(request, 'Overlay created from JSON.')
                    return redirect('overlays_list')
                except Exception as e:
                    messages.error(request, f"Invalid JSON file: {e}")
    else:
        form = OverlayForm()
        upload_form = OverlayUploadForm()

    return render(request, 'OverlayPages/add-overlay.html', {
        'form': form,
        'upload_form': upload_form
    })



@login_required
@role_required('client')
def delete_overlay(request, overlay_id):
    overlay = get_object_or_404(Overlay, id=overlay_id, user=request.user)
    overlay.delete()
    messages.success(request, 'Overlay deleted.')
    return redirect('overlays_list')
