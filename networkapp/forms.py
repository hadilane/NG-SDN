# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import *
from django.contrib.auth.forms import PasswordResetForm

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


class OverlayForm(forms.ModelForm):
    class Meta:
        model = Overlay
        
        fields = ['name', 'status', 'switches', 'topology']
        widgets = {
            'switches': forms.Textarea(attrs={'rows': 4}),
            'topology': forms.Textarea(attrs={'rows': 4}),
        }

    def __init__(self, *args, **kwargs):
        super(OverlayForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})

class OverlayUploadForm(forms.Form):
    json_file = forms.FileField()

    def __init__(self, *args, **kwargs):
        super(OverlayUploadForm, self).__init__(*args, **kwargs)
        self.fields['json_file'].widget.attrs.update({'class': 'form-control'})




