from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.



class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ('admin', 'Admin'),
        ('client', 'Client'),
    )
    role = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='client')

    def is_admin(self):
        return self.role == 'admin'

    def is_client(self):
        return self.role == 'client'

class Overlay(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)