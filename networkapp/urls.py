from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .forms import CustomPasswordResetForm
from .views import *
from django.conf import settings



urlpatterns = [
    path('', views.login_view, name='login'),
    path('Home/', views.home, name='home'),
    path('topology/', views.view_topology, name='topology'),
    path('Dashboard/', views.dashboard, name='dashboard'),
    path('topology-data/', views.get_onos_topology, name='get_onos_topology'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('password_reset/',CustomPasswordResetView.as_view(),name='password_reset' ),     
    path( 'password_reset_done/',auth_views.PasswordResetDoneView.as_view(template_name='Authentication/password_reset_done.html'),name='password_reset_done'),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(template_name='Authentication/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/',auth_views.PasswordResetCompleteView.as_view(template_name='Authentication/password_reset_complete.html'), name='password_reset_complete'),
    path('clients/', views.clients_list, name='clients'),  
    path('clients/delete/<int:user_id>/', views.delete_client, name='delete_client'),
    path('clients/toggle/<int:user_id>/', views.toggle_client_status, name='toggle_client_status'),
    path('overlays/', views.overlays_list, name='overlays_list'),
    #path('overlays/add/', views.add_overlay, name='add_overlay'),
    path('overlays/<int:overlay_id>/', views.overlay_detail, name='overlay_detail'),
    path('overlays/<int:overlay_id>/delete/', views.delete_overlay, name='delete_overlay'),
    path('profile/', profile_view, name='client_profile'),
    path('adminprofile/', views.adminprofile_view, name='admin_profile'),
    path('logout/', views.logout_view, name='logout'),
    path('clients/<int:client_id>/profile/', views.client_profile_view, name='client_profile'),
    path('clients/<int:client_id>/profile/history/', views.admin_clients_detailed_history, name='admin_clients_detailed_history'),
    path('create/demande/', views.create_demande_overlay, name='create_demande_overlay'),
    path('demandes/', views.liste_demandes_client, name='liste_demandes_client'),
    path('list/demandes/', views.liste_demandes_admin, name='liste_demandes_admin'),
    path('lists/demandes/<int:demande_id>/', views.demande_detail_client, name='demande_detail_client'),
    path('list/demandes/<int:demande_id>/', views.demande_detail, name='demande_detail'),
    path('list/demandes/<int:demande_id>/valider/', views.valider_demande_overlay, name='valider_demande'),
    path('list/demandes/<int:demande_id>/rejeter/', views.rejeter_demande_overlay, name='rejeter_demande'),
    path('notifications/read/', views.mark_notifications_read, name='mark_notifications_read'),
    path('demandes/delete/<int:demande_id>/', views.delete_demande, name='delete_demande'),
    path('generate-telemetry-report/', views.generate_telemetry_report, name='generate_telemetry_report'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
]