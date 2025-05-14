from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .forms import CustomPasswordResetForm
from .views import CustomPasswordResetView
from django.conf import settings



urlpatterns = [
    path('', views.login_view, name='login'),
    path('Home/', views.home, name='home'),
    path('topology/', views.view_topology, name='topology'),
    path('Dashboard/', views.dashboard, name='dashboard'),
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
    path('overlays/add/', views.add_overlay, name='add_overlay'),
    path('overlays/<int:overlay_id>/', views.overlay_detail, name='overlay_detail'),
    path('overlays/<int:overlay_id>/delete/', views.delete_overlay, name='delete_overlay'),

]