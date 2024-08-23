# from celery import shared_task
# from .models import User

# @shared_task
# def check_expired_sessions():
#     from django.utils import timezone
#     now = timezone.now()
#     users = User.objects.filter(logout__isnull=True, estimated_logout__lte=now)
#     for user in users:
#         user.logout = now
#         user.save()

from celery import shared_task
from django.utils import timezone
from .models import User
import logging
logger = logging.getLogger(__name__)

@shared_task
def check_expired_sessions():
    now = timezone.now()
    users = User.objects.filter(logout__isnull=True, estimated_logout__lte=now)
    for user in users:
        logger.info(f"Updating logout time for user {user.id}")
        user.logout = now
        user.save()
        logger.info(f"Logout time updated for user {user.id}")

