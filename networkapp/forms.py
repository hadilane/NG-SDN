# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import *
from django.contrib.auth.forms import PasswordResetForm
from .models import DemandeOverlay

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = [
            'username', 'email', 'phone', 'department', 
            'password1', 'password2', 'photo', 'role'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'form-control',
                'placeholder': field.label
            })

        # For file input (image upload)
        self.fields['photo'].widget.attrs.update({
            'class': 'form-control dropify'
        })

class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))




class CustomPasswordResetForm(PasswordResetForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({
                'class': 'form-control',
                'placeholder': field.label
            })


# class OverlayForm(forms.ModelForm):
#     class Meta:
#         model = Overlay
        
#         fields = ['name', 'status', 'switches', 'topology']
#         widgets = {
#             'switches': forms.Textarea(attrs={'rows': 4}),
#             'topology': forms.Textarea(attrs={'rows': 4}),
#         }

#     def __init__(self, *args, **kwargs):
#         super(OverlayForm, self).__init__(*args, **kwargs)
#         for field in self.fields.values():
#             field.widget.attrs.update({'class': 'form-control'})

class OverlayUploadForm(forms.Form):
    json_file = forms.FileField()

    def __init__(self, *args, **kwargs):
        super(OverlayUploadForm, self).__init__(*args, **kwargs)
        self.fields['json_file'].widget.attrs.update({'class': 'form-control'})



class DemandeOverlayForm(forms.ModelForm):
    overlay_name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))
    overlay_type = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))
    overlay_status = forms.ChoiceField(choices=[('Active', 'Active'), ('Inactive', 'Inactive')], widget=forms.Select(attrs={'class': 'form-control'}))
    overlay_description = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}), required=False)
    overlay_tunnel_mode = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))

    class Meta:
        model = DemandeOverlay
        fields = ['overlay_name', 'overlay_type', 'overlay_status', 'overlay_description', 'overlay_tunnel_mode']

    def clean(self):
        cleaned_data = super().clean()
        device_names = self.data.getlist('device_name[]')
        device_lan_interfaces = self.data.getlist('device_LAN_interface[]')

        if len(device_names) != len(device_lan_interfaces):
            raise forms.ValidationError("Number of device names and LAN interfaces must match.")

        segments = []
        for name, iface in zip(device_names, device_lan_interfaces):
            if name and iface:
                segments.append({"device_name": name, "device_LAN_interface": iface})

        if not segments:
            raise forms.ValidationError("At least one valid segment is required.")

        cleaned_data['configuration'] = {"overlay_segments": segments}
        return cleaned_data
