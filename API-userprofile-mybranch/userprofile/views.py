from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from helper.views import *
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import ApplicationSerializer,UserDataSerializer
from . models import *
from django.http import HttpRequest
from rest_framework.response import Response
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db import transaction
import pytz
from django.db.models import F
from rest_framework import status


@method_decorator(csrf_exempt,name='dispatch')
class getProfile(APIView):
    def get(self,request,*args,**kwargs):
        # tokenresponse = checkToken(request)
        # UserData , token = tokenresponse
        # print(UserData)
        
        print(f"user_id-------->{request.UserData.id}")
        print(f"application_id-------->{request.UserData.application_id}")
        print(f"user_email-------->{request.UserData.email}")
        response_data = {'message': 'Profile data retrieved successfully.'}
        user_serializer = UserDataSerializer(request.UserData)
        print(user_serializer.data)
        User = user_serializer.data
        print('...........................................................')
        print(User)
        # del User['_state']
        application = GetApplication(request.UserData.application_id)
        User['application'] = application['application_name']
        return Response(User)
        return Response(response_data)

class getTeam(APIView):
    # permission_classes=(IsAuthenticated,)
    def get(self,request,*args,**kwargs):
        # tokenresponse = checkToken(request)
        # UserData , token = tokenresponse
        # print(UserData)
        print(f"user_id-------->{request.UserData.id}")
        print(f"application_id-------->{request.UserData.application_id}")
        print(f"user_email-------->{request.UserData.email}")
        application_id = request.UserData.application_id
        print("<============================================>")
        print(f"application_id:--------------------------------------> {application_id}")
        user_id = request.UserData.id
        print(f"user_id:--------------------------------------> {user_id}")
        child_roles = GetChild(application_id, user_id)
        print(f"child_roles:-----------------------> {child_roles}")
        if not child_roles:
            child_roles = [user_id]
        else:
            child_roles = [int(role_id) for role_id in child_roles]

        print(f"child_roles:-----------------------> {child_roles}")
        print("<============================================>")
        try:
            users = User.objects.filter(application_id=application_id, id__in=child_roles)
        except ValidationError as e:
            response_data = {'error': str(e)}
            return Response(response_data, status=400)
        print(f"users:--------------------------------------> {users}")

        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'name': user.name,
                # Include other user fields as needed
            })
    
        return JsonResponse(user_data, safe=False)


#_______________________________________Generate OTP____________________________________________

OTP_LENGTH = 6

# Generate OTP
def generate_otp():
    return ''.join(random.choices('0123456789', k=OTP_LENGTH))

# API endpoint for sending OTP via email and validating it
class SendAndVerifyOTP(APIView):############
    #@method_decorator(csrf_exempt)
    def post(self, request):
        # Get email and OTP from request data
        email = request.data.get('email')
        otp_entered = request.data.get('otp')
        #print(email)
        # If OTP is not provided, send OTP to the email
        if not otp_entered:
            # Validate email format
            if not email:
                return JsonResponse({'error': 'Email address is required'}, status=400)
            if not '@' in email or not '.' in email:
                return JsonResponse({'error': 'Invalid email address'}, status=400)
            # Generate OTP
            otp = generate_otp()
            #print(otp)
            # Save OTP in database
            user = User.objects.get(email=email)
            email_log = EmailsLogs.objects.create(
                sended_by='noreply',
                added_by=user,
                sended_to=email,
                is_send=1,
                message=f'Your OTP is: {otp}',  # Include OTP in message
                sent_date=datetime.now(),
                is_otp=True,
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return JsonResponse({'message': 'OTP generated successfully'})



#_________________________Resend OTP_______________________________________________________

class Resend_OTP(APIView):
    OTP_LENGTH = 6

    def generate_otp(self):
        return ''.join(random.choices('0123456789', k=self.OTP_LENGTH))

    @method_decorator(csrf_exempt)
    def post(self, request):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User not found'}, status=400)
        
        # Check if forget password attempts have exceeded the limit
        if user.forget_password_attempts >= 5:
            return JsonResponse({'message': 'Forget password attempts exceeded. Your account has been blocked.'}, status=403)
        
        

        otp = self.generate_otp()
        print(otp)
        otp_expiry = timezone.now() + timedelta(minutes=10)  # Set OTP validity for 10 minutes

        # Check for existing OTP for the user before saving
        existing_otp = EmailsLogs.objects.filter(added_by=user, is_otp=True).order_by('-id').first()
        if existing_otp and existing_otp.sent_date > timezone.now() - timedelta(minutes=10):
            pass 

        email_log = EmailsLogs.objects.create(
            sended_by='no-reply',
            added_by=user,
            sended_to=email,
            is_send=1,
            message=f'Your OTP is: {otp}',
            sent_date=timezone.now(),
            is_otp=True,
            ip_address=request.META.get('REMOTE_ADDR'),
            #to_be_sent_date=otp_expiry  # Save the OTP expiry time
            to_be_sent_date=timezone.now() + timedelta(minutes=10)
        )
        
        user.forget_password_attempts += 1
        user.save()
        
        # Check if forget password attempts have reached the limit
        if user.forget_password_attempts >= 5:
            return JsonResponse({'message': 'Forget password attempts exceeded. Your account has been blocked.'}, status=403)


        return JsonResponse({'message': 'OTP Resend successfully'})  


    
#_________________________________________Reset Password/ Forget Password________________________________________________

class ForgotResetPassword(APIView):

    @method_decorator(csrf_exempt)
    def post(self, request):
        # Get email, OTP, new password, and confirm password from request data
        email = request.data.get('email')
        otp_entered = request.data.get('otp')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        # Define password complexity requirements
        password_complexity_regex = (
            '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$#!%*?&])[A-Za-z\d@$!%*?&#]{8,25}$'
        )

        user = None

        # If OTP is not provided, send OTP to the email
        if not otp_entered:
            # Validate email format
            if not email:
                return JsonResponse({'error': 'Email address is required'}, status=400)
            if not '@' in email or not '.' in email:
                return JsonResponse({'error': 'Invalid email address'}, status=400)

            # Check if OTP is expired
            email_log = EmailsLogs.objects.filter(sended_to=email, is_otp=True, is_send=1).order_by('-sent_date').first()
            if not email_log:
                return JsonResponse({'error': 'No OTP found for the provided email address'}, status=400)

            # Check if the user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User with this email does not exist.'}, status=404)

            # Get the latest OTP from the database for the user
            otp = email_log.message.split(':')[-1].strip() # Extract OTP from the message
            print(otp)
            return JsonResponse({'message': f' please fill OTP '})
        

        # If OTP is provided, verify it and reset the password
        else:
            try:
                # Validate email format, OTP, new password, and confirm password
                if not email or not otp_entered or not new_password or not confirm_password:
                    return JsonResponse({'error': 'Email, OTP, new password, and confirm password are required'}, status=400)
                if not '@' in email or not '.' in email:
                    return JsonResponse({'error': 'Invalid email address'}, status=400)
                if len(otp_entered) != OTP_LENGTH:
                    return JsonResponse({'error': f'Invalid OTP format. OTP should be {OTP_LENGTH} digits'}, status=400)
                if new_password != confirm_password:
                    return JsonResponse({'error': 'Passwords do not match.'}, status=400)

                # Verify OTP
                email_log = EmailsLogs.objects.filter(sended_to=email, is_otp=True, is_send=1).order_by('-sent_date').first()
                if not email_log or not email_log.message.endswith(otp_entered):
                    # Increment forget_password_attempts when OTP verification fails
                    if user:
                        user.forget_password_attempts = F('forget_password_attempts') + 1
                        user.save()
                    # Check if the user has exceeded the maximum number of attempts
                    if user and user.forget_password_attempts >= 5:
                        # Block the user's account
                        user.account_locked = True
                        user.save()
                        return JsonResponse({'error': 'Account locked. Contact admin.'}, status=403)
                    else:
                        # Calculate and return the remaining attempts
                        attempts_left = 3 - user.forget_password_attempts if user else 5
                        remaining_attempts = max(remaining_attempts, 0)
                        return JsonResponse({'error': f'Invalid OTP. {attempts_left} attempt(s) left.'}, status=400)

                # Check if OTP is expired
                if not email_log or not email_log.message.endswith(otp_entered) or email_log.to_be_sent_date < timezone.now():
                    return JsonResponse({'error': 'expired OTP'}, status=400)

                if email_log.is_read:
                    return JsonResponse({'error': 'OTP has already been used'}, status=400)

                # Validate password length
                if not 6 <= len(new_password) <= 25:
                    return JsonResponse({'error': 'Password must be between 6 and 25 characters'}, status=400)

                # Validate password complexity
                if not re.match(password_complexity_regex, new_password):
                    return JsonResponse({'error': 'Password must contain at least 1 uppercase, 1 lowercase letter, 1 digit, 1 special character'}, status=400)

                # Reset password
                user = email_log.added_by
                user.set_password(new_password)
                user.save()

                # Mark OTP as read
                email_log.is_read = True
                email_log.read_at = datetime.now()
                email_log.save()

                return JsonResponse({'message': 'Password reset successfully'})
            except Exception as e:
                # Log the exception for debugging purposes
                print(f"An error occurred: {e}")
                return JsonResponse({'error': ' Account locked. Contact admin.'}, status=500)



###______________________________________________Validate Email________________________________________________________
#@method_decorator(csrf_exempt)
class ValidateEmail(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp_entered = request.data.get('otp')
        print(otp_entered)
        print(email)
        # Check if OTP matches the one stored in the database for the given email
        email_log = EmailsLogs.objects.filter(sended_to=email, is_otp=True, is_send=1).order_by('-sent_date').first()
        print(email_log)
        if email_log and email_log.message.endswith(otp_entered):
        
            return JsonResponse({'message': 'Email validated successfully'})
        else:
            return JsonResponse({'error': 'Invalid OTP '}, status=400)


#_______________________________________________Account Locked_________________________________________________________

class account_locked(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_login_attempts():
            return Response({"error": "Account locked. Contact admin."}, status=status.HTTP_403_FORBIDDEN)

        if user.check_password(password):
            user.login_attempts = 0
            user.save()
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        else:
            user.login_attempts += 1
            user.save()
            remaining_attempts = 3 - user.login_attempts
            if remaining_attempts > 0:
                return Response({"error": f"Invalid credentials. {remaining_attempts} attempts remaining."},
                                status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"error": "Invalid credentials. Account locked. Contact admin."},
                                status=status.HTTP_401_UNAUTHORIZED)
        


#____________________________________________________User Unblock_______________________________________________________#####

class UnblockUser(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=400)

        # Check if user is blocked
        if user.forget_password_attempts < 5:
            return Response({'message': 'User is not blocked'}, status=400)

        # Check if 24 hours have passed since the last forget password attempt
        if user.last_login and timezone.now() - user.last_login < timezone.timedelta(hours=24):
            return Response({'message': '24 hours have not passed since last attempt'}, status=400)

        # Unblock the user
        user.forget_password_attempts = 0
        user.save()

        return Response({'message': 'User unblocked successfully'})
    
#####_____________________________________________User update there details_____________________________________________-###########

class UpdateUser(APIView):
    
    #Check if the user is authenticated
    # if not request.user.is_authenticated:
    #     return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    
    def get_user_details(self, user):
        return {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email,
            'phone': user.phone,
            'gender': user.gender,
            'profile_pic': user.profile_pic,
            'dob': user.dob,
            'short_name': user.short_name,
        }
    
    
    def get(self, request, user_id):
        existing_user = User.objects.filter(id=user_id).first()
        if not existing_user:
            return Response({'error': 'User with provided ID does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(self.get_user_details(existing_user))
    
    
    
    def put(self, request, user_id):
        data = request.data
        name = data.get('name')
        email = data.get('email')
        
        #Check if the user is authenticated
        # if not request.user.is_authenticated:
        #     return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        # if not name or not email:
        #     return Response({'error': 'Name and email are required'}, status=status.HTTP_400_BAD_REQUEST)

        existing_user = User.objects.filter(id=user_id).first()
        if not existing_user:
            return Response({'error': 'User with provided ID does not exist'}, status=status.HTTP_404_NOT_FOUND)

        # if existing_user.name != name or existing_user.email != email:  # this is need for verify user name eamil Maching 
        #     return Response({'error': 'Name or email does not match the user'}, status=status.HTTP_400_BAD_REQUEST)

        existing_user.first_name = data.get('first_name', existing_user.first_name)
        existing_user.last_name = data.get('last_name', existing_user.last_name)
        existing_user.username = data.get('username', existing_user.username)
        existing_user.phone = data.get('phone', existing_user.phone)
        existing_user.gender = data.get('gender', existing_user.gender)
        existing_user.profile_pic = data.get('profile_pic', existing_user.profile_pic)
        existing_user.dob = data.get('dob', existing_user.dob)
        existing_user.short_name = data.get('short_name', existing_user.short_name)
        existing_user.save()
        return Response({'message': 'User details updated successfully'},status=status.HTTP_200_OK) #'data': self.get_user_details(existing_user)})


        # return Response({'message': 'User details updated successfully', 'data': {
        #     'id': existing_user.id,
        #     'first_name': existing_user.first_name,
        #     'last_name': existing_user.last_name,
        #     'username': existing_user.username,
        #     'email': existing_user.email,
        #     'phone': existing_user.phone,
        #     'gender': existing_user.gender,
        #     'profile_pic': existing_user.profile_pic,
        #     'dob': existing_user.dob,
        #     'short_name': existing_user.short_name,
        # }})

#_________________________________________This API is Handal User And Application Profile_____________________________________###

class UpdateAPIView(APIView):
    def put(self, request):
        data = request.data
        user_id = data.get('user_id')
        application_id = data.get('application_id')

        if user_id is not None:
            return self.update_user(request)
        elif application_id is not None:
            return self.update_application(request)
        else:
            return Response({'error': 'Either user_id or application_id is required'}, status=status.HTTP_400_BAD_REQUEST)

    def update_user(self, request):
        user_id = request.data.get('user_id')
        existing_user = User.objects.filter(id=user_id).first()
        if not existing_user:
            return Response({'error': 'User with provided ID does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        # Handle file upload
        profile_pic = request.FILES.get('profile_pic')
        if profile_pic:
            existing_user.profile_pic.save(profile_pic.name, profile_pic, save=True)

        name = existing_user.name
        email = existing_user.email
        existing_user.first_name = request.data.get('first_name', existing_user.first_name)
        existing_user.last_name = request.data.get('last_name', existing_user.last_name)
        existing_user.username = request.data.get('username', existing_user.username)
        existing_user.email = request.data.get('email', existing_user.email)
        existing_user.phone = request.data.get('phone', existing_user.phone)
        existing_user.gender = request.data.get('gender', existing_user.gender)
        existing_user.profile_pic = request.data.get('profile_pic', existing_user.profile_pic)
        existing_user.dob = request.data.get('dob', existing_user.dob)
        existing_user.short_name = request.data.get('short_name', existing_user.short_name)
        existing_user.save()
         
        # if needs to user details information print then ucomment following  line
        return Response({'message': 'User details updated successfully'},status=status.HTTP_200_OK) #'data': {
        #     'id': existing_user.id,
        #     'name': name,
        #     'email': email,
        #     'first_name': existing_user.first_name,
        #     'last_name': existing_user.last_name,
        #     'username': existing_user.username,
        #     'phone': existing_user.phone,
        #     'gender': existing_user.gender,
        #     'profile_pic': existing_user.profile_pic,
        #     'dob': existing_user.dob,
        #     'short_name': existing_user.short_name,
        # }})

    def update_application(self, request):
        application_id = request.data.get('application_id')
        existing_application = Application.objects.filter(id=application_id).first()
        if not existing_application:
            return Response({'error': 'Application with provided ID does not exist'}, status=status.HTTP_404_NOT_FOUND)

        name = existing_application.name
        email = existing_application.email
        existing_application.application_address = request.data.get('application_address', existing_application.application_address)
        existing_application.is_ats = request.data.get('is_ats', existing_application.is_ats)
        existing_application.application_mobileno = request.data.get('application_mobileno', existing_application.application_mobileno)
        existing_application.license_start_date = request.data.get('license_start_date', existing_application.license_start_date)
        existing_application.license_end_date = request.data.get('license_end_date', existing_application.license_end_date)
        existing_application.website = request.data.get('website', existing_application.website)
        existing_application.application_pan_no = request.data.get('application_pan_no', existing_application.application_pan_no)
        existing_application.application_gst_no = request.data.get('application_gst_no', existing_application.application_gst_no)
        existing_application.default_status_id = request.data.get('default_status_id', existing_application.default_status_id)
        existing_application.default_referrer_id = request.data.get('default_referrer_id', existing_application.default_referrer_id)
        existing_application.secret_key = request.data.get('secret_key', existing_application.secret_key)
        existing_application.state_name = request.data.get('state_name', existing_application.state_name)
        existing_application.logo_url = request.data.get('logo_url', existing_application.logo_url)
        existing_application.application_about = request.data.get('application_about', existing_application.application_about)
        existing_application.billing_name = request.data.get('billing_name', existing_application.billing_name)
        existing_application.save()
        # if needs to Application details information print then ucomment following  line
        return Response({'message': 'Application details updated successfully'},status=status.HTTP_200_OK)#, 'data': {
        #     'id': existing_application.id,
        #     'name': name,
        #     'email': email,
        #     'application_address': existing_application.application_address,
        #     'is_ats': existing_application.is_ats,
        #     'application_mobileno': existing_application.application_mobileno,
        #     'license_start_date': existing_application.license_start_date,
        #     'license_end_date': existing_application.license_end_date,
        #     'website': existing_application.website,
        #     'application_pan_no': existing_application.application_pan_no,
        #     'application_gst_no': existing_application.application_gst_no,
        #     'default_status_id': existing_application.default_status_id,
        # }})


#########__________________________This section working on user Login Activity_____________________________________####

from .serializers import UserLoginActivitySerializer
class UserLoginActivityView(APIView):
    def get(self, request, *args, **kwargs):
        email = request.query_params.get('email', None)
        if email:
            try:
                user = User.objects.get(email=email)
                serializer = UserLoginActivitySerializer(user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Email parameter is required."}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(email=email, password=password)
        if user:
            # Check if the user is already logged in on another device
            if user.is_logged_in_elsewhere():
                return Response({"detail": "You are already logged in on another device. Please log out first."}, status=status.HTTP_403_FORBIDDEN)

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            # Track login activity
            UserActivityLog.objects.create(
                user=user,
                email=email,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                attempt_name='login_success'
            )

            # Update last login time
            user.last_login = timezone.now()
            user.save()

            return Response({
                'access_token': access_token,
                'refresh_token': refresh_token,
            }, status=status.HTTP_200_OK)

        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    

# class LogoutView(APIView):
#     def post(self, request, *args, **kwargs):
#         refresh_token = request.data.get('refresh_token')
#         if refresh_token:
#             try:
#                 with transaction.atomic():
#                     # Blacklist the token
#                     token = RefreshToken(refresh_token)
#                     token.blacklist()
#                     # Get the user (assuming request.user is the authenticated user)
#                     user = request.user
#                     # Get the current time in IST
#                     ist = pytz.timezone('Asia/Kolkata')
#                     logout_time_ist = timezone.now().astimezone(ist)
#                     # Update the logout time in the User model
#                     user.logout = logout_time_ist
#                     user.save()
#                     # Update the logout time in the UserActivityLog model
#                     user_activity_log = UserActivityLog.objects.filter(user=user, is_successful=True, logout_time__isnull=True).last()
#                     if user_activity_log:
#                         user_activity_log.logout_time = logout_time_ist
#                         user_activity_log.save()
#                     else:
#                         UserActivityLog.objects.create(
#                             user=user,
#                             email=user.email,
#                             ip_address=self.get_client_ip(request),
#                             user_agent=request.META.get('HTTP_USER_AGENT', ''),
#                             logout_time=logout_time_ist,
#                             attempt_name='logout'
#                         )

#                 return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
#             except Exception as e:
#                 return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#         return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

#     def get_client_ip(self, request):
#         x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
#         if x_forwarded_for:
#             ip = x_forwarded_for.split(',')[0]
#         else:
#             ip = request.META.get('REMOTE_ADDR')
#         return ip


class LogoutView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            try:
                with transaction.atomic():
                    # Get the current time in IST
                    ist = pytz.timezone('Asia/Kolkata')
                    logout_time_ist = timezone.now().astimezone(ist)

                    # Update the logout time in the User model
                    user.logout = logout_time_ist
                    user.save()

                    # Update the logout time in the UserActivityLog model
                    user_activity_log = UserActivityLog.objects.filter(user=user, is_successful=True, logout_time__isnull=True).last()
                    if user_activity_log:
                        user_activity_log.logout_time = logout_time_ist
                        user_activity_log.save()
                    else:
                        UserActivityLog.objects.create(
                            user=user,
                            email=user.email,
                            ip_address=self.get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            logout_time=logout_time_ist,
                            attempt_name='logout'
                        )

                    # Log out the user by clearing the session
                    request.session.flush()  # This will remove all session data

                return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

################_________________________________This is the section of herning manager_______________________________

from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from .meetingmodels import HiringManagerAvailability
from .serializers import UserAvailabilitySerializer
class UserAvailabilityCreateView(generics.CreateAPIView):
    
    queryset = HiringManagerAvailability.objects.all()
    serializer_class = UserAvailabilitySerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def get(self, request, id=None):
        if id is not None:
            # Attempt to retrieve availability by user ID
            try:
                user_availabilities = HiringManagerAvailability.objects.filter(id=id)
                if user_availabilities.exists():
                    serializer = self.get_serializer(user_availabilities, many=True)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response({'detail': 'User availability not found.'}, status=status.HTTP_404_NOT_FOUND)
            except HiringManagerAvailability.DoesNotExist:
                return Response({'detail': 'User availability not found.'}, status=status.HTTP_404_NOT_FOUND)
        else:
            # Retrieve all user availabilities
            user_availabilities = HiringManagerAvailability.objects.all()
            serializer = self.get_serializer(user_availabilities, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)



    def put(self, request, id=None):
        try:
            user_availability = HiringManagerAvailability.objects.get(id=id)
        except HiringManagerAvailability.DoesNotExist:
            return Response({'detail': 'User availability not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(user_availability, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .meetingmodels import HiringManagerAvailability
from datetime import datetime


# class AvailabilityIntervalView(APIView):
#     def get(self, request, user_id, day_of_week):
#         # Filter availability slots for the given user and day of the week
#         availabilities = HiringManagerAvailability.objects.filter(
#             user__id=user_id,
#             day_of_week=day_of_week
#         ).order_by('start_time')
        
#         if not availabilities.exists():
#             return Response({'detail': 'No availability slots found for the given user and day of the week.'}, status=status.HTTP_404_NOT_FOUND)

#         # Calculate intervals between consecutive slots
#         intervals = []
#         for i in range(1, len(availabilities)):
#             previous_end_time = availabilities[i - 1].end_time
#             current_start_time = availabilities[i].start_time
#             # Calculate interval
#             interval = datetime.combine(datetime.today(), current_start_time) - datetime.combine(datetime.today(), previous_end_time)
#             intervals.append(str(interval))
#         return Response({
#             'user_id': user_id,
#             'day_of_week': day_of_week,
#             'intervals': intervals
#         }, status=status.HTTP_200_OK)

class AvailabilityIntervalView(APIView):
    def get(self, request, user_id, day_of_week):
        availabilities = HiringManagerAvailability.objects.filter(
            user__id=user_id,
            day_of_week=day_of_week
        ).order_by('start_time')
        
        if not availabilities.exists():
            return Response({'detail': 'No availability slots found for the given user and day of the week.'}, status=status.HTTP_404_NOT_FOUND)

        intervals = []
        for i in range(1, len(availabilities)):
            previous_end_time = availabilities[i - 1].end_time
            current_start_time = availabilities[i].start_time
            interval = datetime.combine(datetime.today(), current_start_time) - datetime.combine(datetime.today(), previous_end_time)
            intervals.append(str(interval))

            # Update block_time for the previous availability
            availabilities[i-1].block_time = interval
            availabilities[i-1].save()

        return Response({
            'user_id': user_id,
            'day_of_week': day_of_week,
            'intervals': intervals
        }, status=status.HTTP_200_OK)












# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .meetingmodels import HiringManagerAvailability, HiringManagers
# from datetime import datetime

# class AvailabilityIntervalView(APIView):
#     def get(self, request, user_id,day_of_week):
#         availabilities = HiringManagerAvailability.objects.filter(
#             user_id=user_id,
#             #application_id=application_id,
#             day_of_week=day_of_week
#         ).order_by('start_time')
        
#         if not availabilities.exists():
#             return Response({'detail': 'No availability slots found for the given user, application, and day of the week.'}, status=status.HTTP_404_NOT_FOUND)

#         intervals = []
#         for i in range(1, len(availabilities)):
#             previous_end_time = availabilities[i - 1].end_time
#             current_start_time = availabilities[i].start_time
            
#             interval_duration = datetime.combine(datetime.today(), current_start_time) - datetime.combine(datetime.today(), previous_end_time)
            
#             intervals.append({
#                 'day_of_week': day_of_week,
#                 'interval_start': previous_end_time.strftime("%H:%M:%S"),
#                 'interval_end': current_start_time.strftime("%H:%M:%S"),
#                 'interval_duration': str(interval_duration)
#             })

#         # Store the intervals in the block_time JSONField of HiringManagers
#         hiring_manager = HiringManagers.objects.filter(user_id=user_id,).first() #application_id_id=application_id
#         if hiring_manager:
#             if hiring_manager.block_time:
#                 block_time_data = hiring_manager.block_time
#             else:
#                 block_time_data = {}

#             block_time_data['user_id'] = user_id
#             #block_time_data['application_id'] = application_id
#             block_time_data['intervals'] = intervals

#             hiring_manager.block_time = block_time_data
#             hiring_manager.save()

#         return Response({
#             'user_id': user_id,
#             #'application_id': application_id,
#             'intervals': intervals
#         }, status=status.HTTP_200_OK)



