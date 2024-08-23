from xml.etree.ElementInclude import include
from django.contrib import admin
from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


urlpatterns = [
         path('profile/',  views.getProfile.as_view()),
         path('myteam/',  views.getTeam.as_view()),
         #path('api/token/', ObtainTokenView.as_view(), name='obtain_token'),
         #path('user/', include('userprofile.urls')),
         path('Generate_OTP/', views.SendAndVerifyOTP.as_view(), name='SendAndVerifyOTP'),
         path("Email-Validation/", views.ValidateEmail.as_view(), name="ValidateEmail"),
         path("forget_password/", views.ForgotResetPassword.as_view(), name="forgot_reset_password"),
         path('Resend_OTP/', views.Resend_OTP.as_view(), name='Resend_OTP'),
         path('account_locked/', views.account_locked.as_view(), name='account_locked'),
         path('User_update/<int:user_id>/', views.UpdateUser.as_view(), name='Update_User_Details'),
         path('User&App/', views.UpdateAPIView.as_view(), name='Update_User_and_Application_Details'),
         path('User_unblock/', views.UnblockUser.as_view(), name='UnblockUser'),
         #path('logout/', views.LogoutView.as_view(), name='api-logout'),
         
         
         
        path('user-login-activity/',views.UserLoginActivityView.as_view(), name='user_login_activity'),
        path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
        path('token/refresh/', TokenRefreshView.as_view(), name='token_srefresh'),
        path('logout/',views.LogoutView.as_view(), name='logout'),
        path('login/', views.LoginView.as_view(), name='logout'),
        path('availability/<int:id>/', views.UserAvailabilityCreateView.as_view(), name='user-availability-create'),
        path('availability/', views.UserAvailabilityCreateView.as_view(), name='user-availability-create'),
        path('availability_intervals/<int:user_id>/<str:day_of_week>/', views.AvailabilityIntervalView.as_view(), name='availability-intervals'),

]
