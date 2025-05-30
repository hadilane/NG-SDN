# Generated by Django 5.2 on 2025-05-30 17:22

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('networkapp', '0005_remove_overlay_status_remove_overlay_switches_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='overlay',
            name='status',
            field=models.CharField(default='Active', max_length=50),
        ),
        migrations.AddField(
            model_name='overlay',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='overlays', to=settings.AUTH_USER_MODEL),
        ),
    ]
