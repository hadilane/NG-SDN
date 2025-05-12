from django.urls import path
from . import views

urlpatterns = [
    path('Home/', views.home, name='home'),
    path('topology/', views.view_topology, name='topology'),
    path('Dashboard/', views.dashboard, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
]