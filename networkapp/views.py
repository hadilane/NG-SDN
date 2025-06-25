
from datetime import timezone

import requests
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
import re
import logging
from django.views.generic import FormView
from django.urls import reverse_lazy
from requests.auth import HTTPBasicAuth
from heapq import heappush, heappop
from .models import Notification, DemandeOverlay, Overlay, CustomUser, UnderlayNetwork
import paramiko
import os
from django.core.files.storage import FileSystemStorage



logger = logging.getLogger(__name__)  # for auditing





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
    demandes = DemandeOverlay.objects.all()[:5]
    
    
    # Fetch overlays and their underlay paths
    overlay_colors = ["#FF5733", "#33FF57", "#3357FF", "#FF33A1", "#A133FF"]
    if request.user.role == 'admin':
        overlays = Overlay.objects.filter(status="Active").select_related('user')
    else:
        overlays = Overlay.objects.filter(user=request.user, status="Active")
    
    overlay_info = []
    skipped_overlays = 0  # Track skipped overlays
    for idx, overlay in enumerate(overlays):
        if not overlay.user:
            logger.warning("Overlay %s (ID: %d) has no associated user", overlay.name, overlay.id)
            skipped_overlays += 1
            continue  # Skip overlays with no user
        underlay = UnderlayNetwork.objects.filter(overlay=overlay).first()
        path = underlay.switches if underlay else []
        config = overlay.configuration or []
        src_device = config[0].get("device_name") if isinstance(config, list) and len(config) > 0 else "N/A"
        src_interface = config[0].get("device_LAN_interface") if isinstance(config, list) and len(config) > 0 else "N/A"
        dst_device = config[1].get("device_name") if isinstance(config, list) and len(config) > 1 else "N/A"
        dst_interface = config[1].get("device_LAN_interface") if isinstance(config, list) and len(config) > 1 else "N/A"
        
        overlay_info.append({
            'name': overlay.name,
            'color': overlay_colors[idx % len(overlay_colors)],
            'user_email': overlay.user.email,
            'src_device': src_device,
            'src_interface': src_interface,
            'dst_device': dst_device,
            'dst_interface': dst_interface,
            'path': " → ".join(path) if path else "No path",
        })

    context = {
        'demandes': demandes,
        'user': request.user,
        'overlay_info': overlay_info,
        'skipped_overlays': skipped_overlays,  # Add to context
        'page_title': 'Admin Dashboard',
    }
    return render(request, 'Adminpages/dashboard.html', context)


def dijkstra(graph, start, end):
    """Find shortest path using Dijkstra's algorithm."""
    queue = [(0, start, [start])]
    visited = set()
    while queue:
        (cost, node, path) = heappop(queue)
        if node in visited:
            continue
        visited.add(node)
        if node == end:
            return path
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                heappush(queue, (cost + 1, neighbor, path + [neighbor]))
    return []



ONOS_URL = "http://193.194.66.123:8181/onos/v1"  # ONOS IP
ONOS_AUTH = HTTPBasicAuth("onos", "rocks")
REQUEST_TIMEOUT = 30  # seconds

def get_onos_topology(request):
    try:
        # Fetch devices
        logger.debug("Fetching devices from %s/devices", ONOS_URL)
        devices_response = requests.get(
            f"{ONOS_URL}/devices",
            auth=ONOS_AUTH,
            timeout=REQUEST_TIMEOUT
        )
        devices_response.raise_for_status()
        devices = devices_response.json().get("devices", [])
        logger.debug("Found %d devices", len(devices))

        # Fetch links
        logger.debug("Fetching links from %s/links", ONOS_URL)
        try:
            links_response = requests.get(
                f"{ONOS_URL}/links",
                auth=ONOS_AUTH,
                timeout=REQUEST_TIMEOUT
            )
            links_response.raise_for_status()
            links = links_response.json().get("links", [])
            logger.debug("Found %d links", len(links))
        except requests.RequestException as e:
            logger.warning("Failed to fetch links: %s", str(e))
            links = []

        # Process devices
        nodes = []
        for device in devices:
            device_id = device.get("id")
            if not device_id:
                logger.warning("Device missing ID: %s", device)
                continue
            available = device.get("available", False)
            annotations = device.get("annotations", {})
            management_address = annotations.get("managementAddress", "N/A")
            ip_address = "N/A" if management_address.startswith("grpc://") else management_address
            
            # Fetch ports
            logger.debug("Fetching ports for device %s", device_id)
            try:
                ports_response = requests.get(
                    f"{ONOS_URL}/devices/{device_id}/ports",
                    auth=ONOS_AUTH,
                    timeout=REQUEST_TIMEOUT
                )
                ports_response.raise_for_status()
                ports = [p["port"] for p in ports_response.json().get("ports", []) if p.get("isEnabled")]
                ports_str = ", ".join(ports) if ports else ""
            except requests.RequestException as e:
                logger.error("Failed to fetch ports for %s: %s", device_id, str(e))
                ports_str = "Error"

            nodes.append({
                "id": device_id,
                "label": f"{device_id} ({'Online' if available else 'Offline'})",
                "title": f"IP: {ip_address}\nPorts: {ports_str}\nStatus: {'Online' if available else 'Offline'}",
                "group": "switch",
                "image": "/static/assets/images/switch-icon.png",
                "shape": "image",
                "color": "#28a745" if available else "#dc3545",
            })

        # Build graph for shortest path
        graph = {}
        for link in links:
            src = link.get("src", {}).get("device")
            dst = link.get("dst", {}).get("device")
            if src and dst:
                if src not in graph:
                    graph[src] = []
                if dst not in graph:
                    graph[dst] = []
                graph[src].append(dst)
                graph[dst].append(src)  # Undirected

        # Process underlay links
        edges = []
        seen_links = set()
        for link in links:
            src = link.get("src", {}).get("device")
            dst = link.get("dst", {}).get("device")
            src_port = link.get("src", {}).get("port", "")
            dst_port = link.get("dst", {}).get("port", "")
            src_port_num = re.search(r'\((\d+)\)', src_port)
            src_port_num = src_port_num.group(1) if src_port_num else src_port
            dst_port_num = dst_port

            if not (src and dst and src_port_num and dst_port_num):
                logger.warning("Invalid link data: %s", link)
                continue
            link_key = tuple(sorted([src, dst]))
            if link_key not in seen_links:
                seen_links.add(link_key)
                reverse_link = next(
                    (l for l in links if l.get("src", {}).get("device") == dst and l.get("dst", {}).get("device") == src),
                    None
                )
                if reverse_link:
                    rev_src_port = reverse_link.get("src", {}).get("port", "")
                    rev_src_port_num = re.search(r'\((\d+)\)', rev_src_port)
                    rev_src_port_num = rev_src_port_num.group(1) if rev_src_port_num else rev_src_port
                    label = f"{src_port_num} ↔ {rev_src_port_num}"
                else:
                    label = f"{src_port_num} → {dst_port_num}"

                edges.append({
                    "from": src,
                    "to": dst,
                    "label": label,
                    "color": "black",
                    "group": "underlay",
                })

        # Process overlays and underlay paths
        logger.debug("Fetching overlays for user %s", request.user)
        if request.user.role == 'admin':
            overlays = Overlay.objects.filter(status="Active")
        else:
            overlays = Overlay.objects.filter(user=request.user, status="Active")
        logger.debug("Found %d overlays", overlays.count())

        overlay_colors = ["#FF5733", "#33FF57", "#3357FF", "#FF33A1", "#A133FF"]
        overlay_edge_ids = []
        for idx, overlay in enumerate(overlays):
            config = overlay.configuration or []
            if not isinstance(config, list) or len(config) < 2:
                logger.debug("Skipping overlay %s: invalid configuration %s", overlay.name, config)
                continue

            src_device = config[0].get("device_name")
            src_interface = config[0].get("device_LAN_interface")
            dst_device = config[1].get("device_name")
            dst_interface = config[1].get("device_LAN_interface")

            if not (src_device and dst_device and src_interface and dst_interface):
                logger.debug("Skipping overlay %s: invalid src=%s or dst=%s or interfaces",
                             overlay.name, src_device, dst_device)
                continue

            # Use stored path from UnderlayNetwork if available
            underlay = UnderlayNetwork.objects.filter(overlay=overlay).first()
            path = underlay.switches if underlay and underlay.switches else dijkstra(graph, src_device, dst_device)
            
            if not path:
                logger.debug("No path found for overlay %s between %s and %s", overlay.name, src_device, dst_device)
                continue

            # Store or update path in UnderlayNetwork
            UnderlayNetwork.objects.update_or_create(
                overlay=overlay,
                defaults={'switches': path}
            )

            # Add overlay path edges
            for i in range(len(path) - 1):
                edge_id = f"overlay_{overlay.id}_{path[i]}_{path[i+1]}"
                overlay_edge_ids.append(edge_id)
                edges.append({
                    "id": edge_id,
                    "from": path[i],
                    "to": path[i+1],
                    "label": overlay.name if i == 0 else "",
                    "color": overlay_colors[idx % len(overlay_colors)],
                    "group": "overlay",
                    "title": f"Overlay: {overlay.name} (Src: {src_interface}, Dst: {dst_interface})",
                    "dashes": True,
                    "width": 4,  # Thicker for highlighting
                })

        logger.debug("Returning %d nodes and %d edges", len(nodes), len(edges))
        return JsonResponse({"nodes": nodes, "edges": edges})

    except requests.ConnectionError as e:
        logger.error("Connection to ONOS failed: %s", str(e))
        return JsonResponse({"error": "Cannot connect to ONOS. Check IP and if ONOS is running."}, status=500)
    except requests.Timeout as e:
        logger.error("ONOS request timed out: %s", str(e))
        return JsonResponse({"error": "ONOS request timed out. Check network or increase timeout."}, status=500)
    except requests.HTTPError as e:
        logger.error("ONOS HTTP error: %s", str(e))
        return JsonResponse({"error": f"ONOS API error: {str(e)}"}, status=500)
    except Exception as e:
        logger.error("Unexpected error in get_onos_topology: %s", str(e), exc_info=True)
        return JsonResponse({"error": f"Internal server error: {str(e)}"}, status=500)
  

# @login_required
# @role_required('admin')
# def dashboard(request):
#     return render(request, 'Adminpages/dashboard.html', {
#         'page_title': 'Dashboard',
#         'user': request.user
#     })


# Registration



# Registration
@login_required
@role_required('admin')
def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, 'Account created. Please login.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'Authentication/register.html', {
        'form': form,
        'page_title': 'Register User'
    })


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
    return render(request, 'Authentication/login.html', {
        'form': form,
        'page_title': 'Login'
    })


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
    messages.success(request, 'Client deleted successfully.')
    return redirect('clients')

@login_required
@role_required('admin')
def toggle_client_status(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id, role='client')
    user.is_active = not user.is_active
    user.save()
    messages.success(request, f"Client {'activated' if user.is_active else 'deactivated'} successfully.")
    return redirect('clients')



@login_required
@role_required('client')
def profile_view(request):
    overlays = Overlay.objects.filter(user=request.user)
    return render(request, 'OverlayPages/client-profile.html', {
        'user': request.user,
        'overlays': overlays,
        'page_title': 'My Profile'
    })


@login_required
@role_required('admin')
def adminprofile_view(request):
    return render(request, 'Adminpages/admin-profile.html', {
        'user': request.user,
        'page_title': 'My Profile'
    })





@login_required
@role_required('admin')  # restrict to admin if needed
def client_profile_view(request, client_id):
    # Fetch the user whose profile is being viewed
    client = get_object_or_404(CustomUser, pk=client_id)
    overlays = client.overlays.all()  # Assuming a related_name 'overlays'

    # Determine the template based on the current user's role
    if request.user.is_authenticated and request.user.is_admin():
        template = 'AdminPages/admin-client-profile.html'  # Admin template
    else:
        template = 'OverlayPages/client-profile.html'  # Client template

    return render(request, template, {
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

        # Determine the template based on the current user's role
    if request.user.is_authenticated and request.user.is_admin():
        template = 'AdminPages/client-overlay-list.html'  # Admin template
    else:
        template = 'OverlayPages/overlays-list.html'  # Client template


    return render(request, template, {
        'overlays': overlays,
        'page_title': 'Overlays List'
    })


@login_required
def overlay_detail(request, overlay_id):
    overlay = get_object_or_404(Overlay, id=overlay_id)
    # Access control: Admins see all, clients see only their overlays
    if not request.user.is_admin() and overlay.user != request.user:
        messages.error(request, "You do not have permission to view this overlay.")
        return redirect('overlays_list')

    # Prepare topology data for client view (overlay only)
    config = overlay.configuration
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError as e:
            logger.error("JSON decode error for overlay %s: %s", overlay.id, str(e))
            config = []

    # Extract source and destination devices from configuration
    topology_data = {
        "nodes": [],
        "links": []
    }

    if isinstance(config, list) and len(config) >= 2:
        src_device = config[0].get("device_name")
        src_interface = config[0].get("device_LAN_interface", "N/A")
        dst_device = config[1].get("device_name")
        dst_interface = config[1].get("device_LAN_interface", "N/A")

        if src_device and dst_device:
            # Add source and destination nodes
            topology_data["nodes"].append({
                "id": src_device,
                "name": src_device,
                "type": "device",
                "interface": src_interface
            })
            topology_data["nodes"].append({
                "id": dst_device,
                "name": dst_device,
                "type": "device",
                "interface": dst_interface
            })
            # Add logical link between source and destination
            topology_data["links"].append({
                "src": src_device,
                "dst": dst_device,
                "type": "overlay"
            })
        else:
            logger.warning("Invalid configuration for overlay %s: src=%s, dst=%s", overlay.id, src_device, dst_device)

    # Determine the template based on the current user's role
    if request.user.is_authenticated and request.user.is_admin():
        template = 'AdminPages/client-overlay-detail.html'  # Admin template
    else:
        template = 'OverlayPages/overlay-detail.html'  # Client template

    return render(request, template, {
        'overlay': overlay,
        'topology_json': topology_data,
        'page_title': f"Overlay Detail: {overlay.name}"
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
                            'page_title': 'Add new Overlay Demand'
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
        'page_title': 'My demandes',
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

   
    return render(request, 'Adminpages/liste_demandes_admin.html', {
        'demandes': demandes,
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
    
    # Validate client exists
    if not demande.client:
        logger.error("DemandeOverlay %s has no client", demande.id)
        messages.error(request, "Cannot validate: No client associated with this demand.")
        return redirect('liste_demandes_admin')

    # Fetch ONOS links for path computation
    try:
        links_response = requests.get(
            f"{ONOS_URL}/links",
            auth=ONOS_AUTH,
            timeout=REQUEST_TIMEOUT
        )
        links_response.raise_for_status()
        links = links_response.json().get("links", [])
        logger.debug("Fetched %d links for path computation", len(links))
    except requests.RequestException as e:
        logger.error("Failed to fetch ONOS links: %s", str(e))
        return render(request, 'Adminpages/valider_demande.html', {
            'demande': demande,
            'error_message': "Failed to fetch ONOS links. Check ONOS connectivity.",
            'page_title': f"Valider Demande: {demande.name}"
        })

    # Build graph for shortest path
    graph = {}
    for link in links:
        src = link.get("src", {}).get("device")
        dst = link.get("dst", {}).get("device")
        if src and dst:
            if src not in graph:
                graph[src] = []
            if dst not in graph:
                graph[dst] = []
            graph[src].append(dst)
            graph[dst].append(src)  # Undirected

    # Extract source and destination from configuration
    config = demande.configuration.get('overlay_segments', [])
    if not (isinstance(config, list) and len(config) >= 2):
        logger.warning("Invalid overlay_segments for demande %s: %s", demande.name, config)
        return render(request, 'Adminpages/valider_demande.html', {
            'demande': demande,
            'error_message': "Invalid overlay configuration.",
            'page_title': f"Valider Demande: {demande.name}"
        })

    src_device = config[0].get("device_name")
    dst_device = config[1].get("device_name")
    if not (src_device and dst_device):
        logger.warning("Invalid src=%s or dst=%s for demande %s", src_device, dst_device, demande.name)
        return render(request, 'Adminpages/valider_demande.html', {
            'demande': demande,
            'error_message': "Invalid source or destination device.",
            'page_title': f"Valider Demande: {demande.name}"
        })

    # Compute shortest path
    path = dijkstra(graph, src_device, dst_device)
    if not path:
        logger.warning("No path found for demande %s between %s and %s", demande.name, src_device, dst_device)
        return render(request, 'Adminpages/valider_demande.html', {
            'demande': demande,
            'error_message': "No valid path found between source and destination.",
            'page_title': f"Valider Demande: {demande.name}"
        })

    if request.method == 'POST':
        # Update demande status
        demande.status = 'validee'
        demande.reviewed_at = timezone.now()
        demande.save()

        # Create Overlay
        overlay = Overlay.objects.create(
            user=demande.client,
            name=demande.name,
            type=demande.configuration.get('overlay_type', ''),
            tunnel_mode=demande.configuration.get('overlay_tunnel_mode', ''),
            status=demande.configuration.get('overlay_status', 'Active'),
            description=demande.description,
            configuration=demande.configuration.get('overlay_segments', {})
        )

        # Handle script uploads
        fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'scripts'))
        config_scripts = {}
        for switch in path:
            script_key = f'script_{switch}'
            if script_key not in request.FILES:
                logger.error("Missing script for switch %s in demande %s", switch, demande.name)
                overlay.delete()  # Roll back overlay creation
                demande.status = 'en_attente'
                demande.save()
                return render(request, 'Adminpages/valider_demande.html', {
                    'demande': demande,
                    'underlay_path': path,
                    'error_message': f"Missing script for switch {switch}.",
                    'page_title': f"Valider Demande: {demande.name}"
                })
            script_file = request.FILES[script_key]
            if not script_file.name.endswith('.py'):
                logger.error("Invalid file type for switch %s: %s", switch, script_file.name)
                overlay.delete()
                demande.status = 'en_attente'
                demande.save()
                return render(request, 'Adminpages/valider_demande.html', {
                    'demande': demande,
                    'underlay_path': path,
                    'error_message': f"File for {switch} must be a .py file.",
                    'page_title': f"Valider Demande: {demande.name}"
                })
            filename = f"overlay_{overlay.id}_{switch.replace(':', '_')}.py"
            saved_path = fs.save(filename, script_file)
            config_scripts[switch] = os.path.join('scripts', saved_path)  # Store relative path

        """
        # Commented out: Script execution on VM
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect('192.168.214.133', username='p4sdn', password='p4sdn', timeout=10)
            for switch, script_path in config_scripts.items():
                # Copy script to VM
                with ssh.open_sftp() as sftp:
                    local_path = os.path.join(settings.MEDIA_ROOT, script_path)
                    remote_path = f"/tmp/{os.path.basename(script_path)}"
                    sftp.put(local_path, remote_path)
                # Execute script
                cmd = f"python3 {remote_path}"
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode()
                error = stderr.read().decode()
                if exit_status != 0:
                    logger.error("Script execution failed for %s: %s", switch, error)
                    overlay.delete()
                    demande.status = 'en_attente'
                    demande.save()
                    return render(request, 'Adminpages/valider_demande.html', {
                        'demande': demande,
                        'underlay_path': path,
                        'error_message': f"Script execution failed for {switch}: {error}",
                        'page_title': f"Valider Demande: {demande.name}"
                    })
                logger.info("Script executed for %s: %s", switch, output)
        except Exception as e:
            logger.error("SSH execution failed: %s", str(e))
            overlay.delete()
            demande.status = 'en_attente'
            demande.save()
            return render(request, 'Adminpages/valider_demande.html', {
                'demande': demande,
                'underlay_path': path,
                'error_message': f"Failed to execute scripts: {str(e)}",
                'page_title': f"Valider Demande: {demande.name}"
            })
        finally:
            ssh.close()
        """

        # Save underlay network with scripts
        UnderlayNetwork.objects.create(
            overlay=overlay,
            switches=path,
            config_scripts=config_scripts
        )

        # Update notifications and send email
        Notification.objects.filter(demand=demande).update(is_read=True)
        send_mail(
            'Demande validée',
            f"Votre demande d'overlay '{demande.name}' a été validée. Scripts ont été enregistrés.",
            settings.DEFAULT_FROM_EMAIL,
            [demande.client.email]
        )
        messages.success(request, "Demande validated, scripts saved, and overlay created.")
        return redirect('liste_demandes_admin')
    
    return render(request, 'Adminpages/valider_demande.html', {
        'demande': demande,
        'underlay_path': path,
        'page_title': f"Valider Demande: {demande.name}"
    })

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
        messages.warning(request, "Demande rejected.")
        return redirect('liste_demandes_admin')
    return render(request, 'Adminpages/rejeter_demande.html', {
        'demande': demande,
        'page_title': f"Rejeter Demande: {demande.name}"
    })

@login_required
@role_required('admin')
def mark_notifications_read(request):
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    messages.success(request, "All notifications marked as read.")
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
