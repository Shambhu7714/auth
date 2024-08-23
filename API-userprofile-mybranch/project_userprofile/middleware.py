# # myapp/middleware.py

# from rest_framework_simplejwt.authentication import JWTAuthentication
# from django.http import JsonResponse

# class JWTAuthenticationMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         # Process the request before the view is called
#         if request.path.startswith('/department/'):  # Adjust the path as needed
#             user, _ = self.check_token(request)
#             if not user:
#                 return JsonResponse({'error': 'Unauthorized'}, status=401)

#         response = self.get_response(request)

#         # Process the response after the view is called

#         return response

#     def check_token(self, request):
#         # Extract and validate the JWT token
#         authorization_header = request.headers.get('Authorization', '')
#         if not authorization_header.startswith('Bearer '):
#             return None, None
#         token = authorization_header[len('Bearer '):]
#         jwt_authenticator = JWTAuthentication()

#         try:
#             user, token = jwt_authenticator.authenticate_credentials(token)
#             request.user = user  # Set the user on the request for later use
#             return user, token
#         except Exception as e:
#             return None, None

    
    
    
    
#MIDDLEWARE FOR NULL OR ANYTHING EXCEPTION
# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework_simplejwt.exceptions import InvalidToken
# from django.http import HttpResponse

# class TokenMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         token = request.headers.get('Authorization')

#         if token:
#             # Check if the token format is valid (starts with "Bearer ")
#             if not token.startswith('Bearer '):
#                 return self.invalid_token_response(request)

#             # Extract the token after removing "Bearer "
#             token = token.split('Bearer ')[1].strip()

#             try:
#                 JWT_authenticator = JWTAuthentication()
#                 response = JWT_authenticator.authenticate(request)
#                 if response:
#                     UserData, token = response
#                     request.UserData = UserData
#                     request.token = token
#                     return self.get_response(request)
#                 else:
#                     return self.invalid_token_response(request)
#             except InvalidToken:
#                 return self.invalid_token_response(request)
#         else:
#             return self.unauthorized_response(request)

#     def invalid_token_response(self, request):
#         return HttpResponse(status=401, content='Invalid token', content_type='text/plain')

#     def unauthorized_response(self, request):
#         return HttpResponse(status=401, content='Unauthorized: Token is missing', content_type='text/plain')



from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from userprofile.models import UserActivityLog
from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)

class TokenExpiryMiddleware(MiddlewareMixin):

    def process_request(self, request):
        user = request.user
        if user.is_authenticated:
            now = timezone.now()
            session_duration = timedelta(seconds=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())

            # Log user information for debugging
            logger.debug(f"User {user.email}: last_login={user.last_login}, logout={user.logout}, now={now}")

            # Only update logout time if it's past the user's logout time or if they haven't logged out yet
            if (user.logout and now > user.logout) or not user.logout:
                user.logout = now + session_duration
                user.save()

        return self.get_response(request)



    def track_activity(self, user, token, request):
            # Fetch the last activity
            activity_log = UserActivityLog.objects.filter(user=user, logout_time__isnull=True).first()

            if activity_log:
                # Check if the user is logging in from another device
                if activity_log.ip_address != self.get_client_ip(request):
                    return JsonResponse({'error': 'User already logged in on another device'}, status=400)
                else:
                    # Extend session if necessary
                    activity_log.update_logout_time()

            else:
                # Create a new login activity log
                UserActivityLog.objects.create(
                    user=user,
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    attempt_name='login_success'
                )

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip