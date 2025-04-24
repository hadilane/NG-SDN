from django.urls import path
from . import views

urlpatterns = [
    path('Home/', views.home, name='home'),
      path('topology/', views.view_topology, name='topology'),
]