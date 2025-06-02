from .models import Notification

def admin_notifications(request):
    if request.user.is_authenticated and request.user.role == 'admin':
        notifications = Notification.objects.filter(user=request.user, is_read=False).order_by('-created_at')
        notification_count = notifications.count()
        return {
            'notifications': notifications,
            'notification_count': notification_count
        }
    return {}