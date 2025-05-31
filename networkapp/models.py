from django.db import models
from django.contrib.auth.models import AbstractUser




class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ('admin', 'Admin'),
        ('client', 'Client'),
    )
    role = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='client')

    # ✅ Additional fields
    phone = models.CharField(max_length=20, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    photo = models.ImageField(upload_to='user_photos/', blank=True, null=True)

    def is_admin(self):
        return self.role == 'admin'

    def is_client(self):
        return self.role == 'client'


class Overlay(models.Model):
    name = models.CharField(max_length=100)
    type = models.CharField(max_length=100,default="")
    tunnel_mode = models.CharField(max_length=100,default="")
    status = models.CharField(max_length=50,default="Active")
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='overlays', null=True)
    description = models.TextField(default="No description")  # 👈 Add default here
    configuration = models.JSONField(default=dict)  # 👈 default empty dict
    created_at = models.DateTimeField(auto_now_add=True)

class DemandeOverlay(models.Model):
    STATUS_CHOICES = [
        ('en_attente', 'En attente'),
        ('validee', 'Validée'),
        ('rejetee', 'Rejetée'),
    ]

    client = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    configuration = models.JSONField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='en_attente')
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    commentaire_admin = models.TextField(blank=True)


class Notification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    message = models.TextField()
    demand = models.ForeignKey('DemandeOverlay', on_delete=models.SET_NULL, null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user}: {self.message}"