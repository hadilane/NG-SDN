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
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='overlays')
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)
    switches = models.JSONField(blank=True, null=True)  # Store switches or topology info
    topology = models.JSONField(blank=True, null=True)  # Optional: Separate field for full topology
