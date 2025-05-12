# decorators.py
from django.core.exceptions import PermissionDenied

def role_required(role):
    """ Restrict view to users with specific role """
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            if request.user.is_authenticated and request.user.role == role:
                return view_func(request, *args, **kwargs)
            raise PermissionDenied
        return _wrapped_view
    return decorator
