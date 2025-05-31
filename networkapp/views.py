
from datetime import timezone
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
from .forms import *
from django.views.decorators.http import require_http_methods
from django.db.models import Q
from django.shortcuts import render, get_object_or_404
from django.contrib.admin.views.decorators import staff_member_required
from .models import *
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.core.mail import EmailMultiAlternatives, send_mail
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.db.models import Q
from django.conf import settings
from .forms import CustomUserCreationForm, CustomAuthenticationForm, CustomPasswordResetForm, DemandeOverlayForm, OverlayUploadForm
from .models import CustomUser, Overlay, DemandeOverlay, Notification
from datetime import datetime, timezone as tz
from django.utils.crypto import get_random_string
import json
import logging
from django.views.generic import FormView
from django.urls import reverse_lazy





# Create your views here.

def home(request):
    overlays = Overlay.objects.filter(user=request.user)
    return render(request, 'home.html', {'overlays': overlays,'page_title': 'Home'})



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
    notifications = Notification.objects.filter(user=request.user, is_read=False).order_by('-created_at')
    notification_count = notifications.count()
    return render(request, 'Adminpages/dashboard.html', {
        'page_title': 'Dashboard',
        'notifications': notifications,
        'notification_count': notification_count,
        'user': request.user
    })


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
                return redirect('clients')
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
    query = request.GET.get('search', '').strip()
    clients = CustomUser.objects.filter(role='client')

    if query:
        clients = clients.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        )


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
            active_tab = 'addnew'
    else:
        form = CustomUserCreationForm()
        active_tab = 'list'

    return render(request, 'Adminpages/project-clients.html', {
        'clients': clients.distinct(),
        'form': form,
        'active_tab': active_tab,
        'page_title': 'Clients List',
        'search_query': query,
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



@login_required
@role_required('client')
def profile_view(request):
    overlays = Overlay.objects.filter(user=request.user)
    return render(request, 'OverlayPages/client-profile.html', {
        'user': request.user,
        'overlays': overlays,
        'page_title': 'My profile'
    })


@login_required
@role_required('admin')
def adminprofile_view(request):
    return render(request, 'Adminpages/admin-profile.html', {
        'user': request.user,
        'page_title': 'My profile'
    })





@login_required
@role_required('admin')  # Optional: restrict to admin if needed
def client_profile_view(request, client_id):
    client = get_object_or_404(CustomUser, pk=client_id)
    overlays = client.overlays.all()
    return render(request, 'OverlayPages/client-profile.html', {
        'user': client,
        'overlays': overlays,
        'page_title': f"{client.first_name} {client.last_name}'s Profile"
    })


# Overlay section ----------------------------------

@login_required
def overlays_list(request):
    if request.user.is_admin():
        overlays = Overlay.objects.all()  # Admin sees all overlays
    else:
        overlays = Overlay.objects.filter(user=request.user)  # Clients see only theirs

    overlay_id = request.GET.get('id')
    status = request.GET.get('status')
    name = request.GET.get('name')
    date = request.GET.get('date')

    if overlay_id:
        overlays = overlays.filter(id=overlay_id)
    if status:
        overlays = overlays.filter(status__iexact=status)
    if name:
        overlays = overlays.filter(name__icontains=name)
    if date:
        overlays = overlays.filter(created_at__date=date)

    return render(request, 'OverlayPages/overlays-list.html', {
        'overlays': overlays,
        'page_title': 'Overlays List'
    })


@login_required
def overlay_detail(request, overlay_id):
    overlay = get_object_or_404(Overlay, id=overlay_id)
    if not request.user.is_admin() and overlay.user != request.user:
        return redirect('overlays_list')
    if isinstance(overlay.configuration, str):
        try:
            config_data = json.loads(overlay.configuration)
        except json.JSONDecodeError as e:
            print("JSON Error:", e)
            config_data = {}
    else:
        config_data = overlay.configuration
    return render(request, 'OverlayPages/overlay-detail.html', {
        'overlay': overlay,
        'topology_json': config_data,
        'page_title': 'Overlay detail'
    })





# @login_required
# @role_required('client')
# def add_overlay(request):
#     if request.method == 'POST':
#         if 'submit_form' in request.POST:
#             form = OverlayForm(request.POST)
#             upload_form = OverlayUploadForm()  # Empty, skip validation
#             if form.is_valid():
#                 overlay = form.save(commit=False)
#                 overlay.user = request.user
#                 overlay.switches = form.cleaned_data.get('switches', {}) or {}
#                 overlay.topology = form.cleaned_data.get('topology', {}) or {}
#                 overlay.save()
#                 messages.success(request, 'Overlay added successfully.')
#                 return redirect('overlays_list')
#         elif 'submit_json' in request.POST:
#             form = OverlayForm()  # Empty, skip validation
#             upload_form = OverlayUploadForm(request.POST, request.FILES)
#             if upload_form.is_valid():
#                 json_file = upload_form.cleaned_data['json_file']
#                 try:
#                     data = json.load(json_file)
#                     name = data.get('name', 'Unnamed Overlay')
#                     status = data.get('status', 'Unknown')
#                     overlay = Overlay.objects.create(
#                         user=request.user,
#                         name=name,
#                         status=status,
#                         switches=data.get('switches', {}),
#                         topology=data.get('topology', {})
#                     )
#                     messages.success(request, 'Overlay created from JSON.')
#                     return redirect('overlays_list')
#                 except Exception as e:
#                     messages.error(request, f"Invalid JSON file: {e}")
#     else:
#         form = OverlayForm()
#         upload_form = OverlayUploadForm()

#     return render(request, 'OverlayPages/add-overlay.html', {
#         'form': form,
#         'upload_form': upload_form,
#         'page_title': 'Add overlay '
#     })



@login_required
@role_required('client')
def delete_overlay(request, overlay_id):
    overlay = get_object_or_404(Overlay, id=overlay_id, user=request.user)
    overlay.delete()
    messages.success(request, 'Overlay deleted.')
    return redirect('overlays_list')


@login_required
@role_required('client')
def create_demande_overlay(request):
    if request.method == 'POST':
        if 'submit_form' in request.POST:
            form = DemandeOverlayForm(request.POST)
            upload_form = OverlayUploadForm()
            if form.is_valid():
                demande = form.save(commit=False)
                demande.client = request.user
                demande.name = form.cleaned_data['overlay_name']
                demande.description = form.cleaned_data['overlay_description']
                demande.configuration = form.cleaned_data['configuration']
                demande.status = 'en_attente'
                demande.save()
                # Create notification for admin
                admins = CustomUser.objects.filter(role='admin')
                for admin in admins:
                    Notification.objects.create(
                        user=admin,
                        message=f"New overlay demand '{demande.name}' from {request.user.first_name} {request.user.last_name}",
                        demand=demande
                    )
                messages.success(request, "Demande envoyée avec succès.")
                return redirect('liste_demandes_client')
        elif 'submit_json' in request.POST:
            form = DemandeOverlayForm()
            upload_form = OverlayUploadForm(request.POST, request.FILES)
            if upload_form.is_valid():
                json_file = upload_form.cleaned_data['json_file']
                try:
                    data = json.load(json_file)
                    required_fields = ['overlay_name', 'overlay_type', 'overlay_status', 'overlay_tunnel_mode', 'overlay_segments']
                    if not all(field in data for field in required_fields):
                        messages.error(request, "JSON file missing required fields.")
                        return render(request, 'OverlayPages/add-overlay.html', {
                            'form': form,
                            'upload_form': upload_form,
                            'page_title': 'Ajouter une demande d’overlay'
                        })
                    demande = DemandeOverlay.objects.create(
                        client=request.user,
                        name=data['overlay_name'],
                        description=data.get('overlay_description', ''),
                        configuration={
                            'overlay_type': data['overlay_type'],
                            'overlay_status': data['overlay_status'],
                            'overlay_tunnel_mode': data['overlay_tunnel_mode'],
                            'overlay_segments': data['overlay_segments']
                        },
                        status='en_attente'
                    )
                    # Create notification for admin
                    admins = CustomUser.objects.filter(role='admin')
                    for admin in admins:
                        Notification.objects.create(
                            user=admin,
                            message=f"New overlay demand '{demande.name}' from {request.user.first_name} {request.user.last_name}",
                            demand=demande
                        )
                    messages.success(request, 'Demande créée à partir du fichier JSON.')
                    return redirect('liste_demandes_client')
                except Exception as e:
                    messages.error(request, f"Fichier JSON invalide : {e}")
        else:
            messages.error(request, "Invalid submission.")
    else:
        form = DemandeOverlayForm()
        upload_form = OverlayUploadForm()
    return render(request, 'OverlayPages/add-overlay.html', {
        'form': form,
        'upload_form': upload_form,
        'page_title': 'Add new overlay creation demande'
})






@login_required
@role_required('client')
def liste_demandes_client(request):
    demandes = DemandeOverlay.objects.filter(client=request.user).order_by('-created_at')

    # Get search parameters
    overlay_id = request.GET.get('id')
    status = request.GET.get('status')
    name = request.GET.get('name')
    date = request.GET.get('date')

    # Apply filters
    if overlay_id:
        demandes = demandes.filter(id=overlay_id)
    if status:
        demandes = demandes.filter(status__iexact=status)
    if name:
        demandes = demandes.filter(name__icontains=name)
    if date:
        try:
            # Assuming date format is YYYY-MM-DD
            demandes = demandes.filter(created_at__date=date)
        except ValueError:
            messages.error(request, "Invalid date format. Use YYYY-MM-DD.")

    return render(request, 'OverlayPages/liste_demandes_client.html', {
        'demandes': demandes,
        'page_title': 'Mes demandes d’overlay',
        'search_query': {
            'id': overlay_id or '',
            'name': name or '',
            'status': status or '',
            'date': date or ''
        }
    })

@login_required
@role_required('admin')
def liste_demandes_admin(request):
    query = request.GET.get('search', '').strip()
    demandes = DemandeOverlay.objects.all().order_by('-created_at')

    # Get search parameters
    overlay_id = request.GET.get('id')
    status = request.GET.get('status')
    name = request.GET.get('name')
    date = request.GET.get('date')

    # Apply filters
    if overlay_id:
        demandes = demandes.filter(id=overlay_id)
    if status:
        demandes = demandes.filter(status__iexact=status)
    if name:
        demandes = demandes.filter(
            Q(name__icontains=name) |
            Q(client__first_name__icontains=name) |
            Q(client__last_name__icontains=name) |
            Q(client__email__icontains=name)
        )
    if date:
        try:
            demandes = demandes.filter(created_at__date=date)
        except ValueError:
            messages.error(request, "Invalid date format. Use YYYY-MM-DD.")

    notifications = Notification.objects.filter(user=request.user, is_read=False).count()
    return render(request, 'Adminpages/liste_demandes_admin.html', {
        'demandes': demandes,
        'notification_count': notifications,
        'page_title': 'Demands list',
        'search_query': {
            'id': overlay_id or '',
            'name': name or '',
            'status': status or '',
            'date': date or ''
        }
    })

@login_required
def demande_detail(request, demande_id):
    demande = get_object_or_404(DemandeOverlay, id=demande_id)
    notification = Notification.objects.filter(user=request.user, demand=demande, is_read=False).first()
    if notification:
        notification.is_read = True
        notification.save()
    return render(request, 'Adminpages/demande_detail.html', {
        'demande': demande,
        'page_title': f"Demande detail: {demande.name}"
    })

@login_required
def demande_detail_client(request, demande_id):
    demande = get_object_or_404(DemandeOverlay, id=demande_id)
    notification = Notification.objects.filter(user=request.user, demand=demande, is_read=False).first()
    if notification:
        notification.is_read = True
        notification.save()
    return render(request, 'OverlayPages/demande_detail_client.html', {
        'demande': demande,
        'page_title': f"Demande detail: {demande.name}"
    })

@login_required
@role_required('admin')
def valider_demande_overlay(request, demande_id):
    demande = get_object_or_404(DemandeOverlay, id=demande_id)
    if request.method == 'POST':
        demande.status = 'validee'
        demande.reviewed_at = timezone.now()
        demande.save()
        Overlay.objects.create(
            user=demande.client,
            name=demande.name,
            type=demande.configuration.get('overlay_type', ''),
            tunnel_mode=demande.configuration.get('overlay_tunnel_mode', ''),
            status=demande.configuration.get('overlay_status', 'Active'),
            description=demande.description,
            configuration=demande.configuration.get('overlay_segments', {})
        )
        Notification.objects.filter(demand=demande).update(is_read=True)
        send_mail(
            'Demande validée',
            f"Votre demande d'overlay '{demande.name}' a été validée.",
            settings.DEFAULT_FROM_EMAIL,
            [demande.client.email]
        )
        messages.success(request, "Demande validée et overlay créé.")
        return redirect('liste_demandes_admin')
    return render(request, 'Adminpages/valider_demande.html', {'demande': demande})


@login_required
@role_required('admin')
def rejeter_demande_overlay(request, demande_id):
    demande = get_object_or_404(DemandeOverlay, id=demande_id)
    if request.method == 'POST':
        commentaire = request.POST.get('commentaire', '')
        demande.status = 'rejetee'
        demande.commentaire_admin = commentaire
        demande.reviewed_at = timezone.now()
        demande.save()
        Notification.objects.filter(demand=demande).update(is_read=True)
        send_mail(
            'Demande rejetée',
            f"Votre demande d'overlay '{demande.name}' a été rejetée. Commentaire : {commentaire}",
            settings.DEFAULT_FROM_EMAIL,
            [demande.client.email]
        )
        messages.warning(request, "Demande rejetée.")
        return redirect('liste_demandes_admin')
    return render(request, 'Adminpages/rejeter_demande.html', {'demande': demande})

@login_required
@role_required('admin')
def mark_notifications_read(request):
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    return redirect('dashboard')



@login_required
@role_required('client')
def delete_demande(request, demande_id):
    demande = get_object_or_404(DemandeOverlay, id=demande_id, client=request.user)
    if request.method == 'POST' or request.method == 'GET':  # Allow GET for simplicity, with confirmation in template
        demande_name = demande.name
        demande.delete()
        
        # Create notification for admins
        admins = CustomUser.objects.filter(role='admin')
        for admin in admins:
            Notification.objects.create(
                user=admin,
                message=f"Overlay demand '{demande_name}' deleted by {request.user.first_name} {request.user.last_name}",
                demand=None  # No demand reference since it's deleted
            )
        
        messages.success(request, f"Demand '{demande_name}' deleted successfully.")
        return redirect('liste_demandes_client')
    
    return redirect('liste_demandes_client')

# @staff_member_required
# def valider_demande_overlay(request, demande_id):
#     demande = DemandeOverlay.objects.get(id=demande_id)
#     demande.status = 'validee'
#     demande.reviewed_at = now()
#     demande.save()

#     # Auto-create overlay
#     Overlay.objects.create(
#         name=demande.name,
#         description=demande.description,
#         configuration=demande.configuration
#     )

#     # Optional: notify client
#     send_mail(
#         'Demande validée',
#         f"Votre demande d'overlay '{demande.name}' a été validée.",
#         'admin@example.com',
#         [demande.client.email]
#     )

#     messages.success(request, "Demande validée et overlay créé.")
#     return redirect('liste_demandes_admin')

# @staff_member_required
# def rejeter_demande_overlay(request, demande_id):
#     demande = DemandeOverlay.objects.get(id=demande_id)
#     if request.method == 'POST':
#         commentaire = request.POST.get('commentaire', '')
#         demande.status = 'rejetee'
#         demande.commentaire_admin = commentaire
#         demande.reviewed_at = now()
#         demande.save()

#         # Optional: notify client
#         send_mail(
#             'Demande rejetée',
#             f"Votre demande d'overlay '{demande.name}' a été rejetée. Commentaire : {commentaire}",
#             'admin@example.com',
#             [demande.client.email]
#         )

#         messages.warning(request, "Demande rejetée.")
#         return redirect('liste_demandes_admin')
#     return render(request, 'admin/rejeter_demande.html', {'demande': demande})
