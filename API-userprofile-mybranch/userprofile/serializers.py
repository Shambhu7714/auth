from rest_framework import serializers
# from authorization.models import User
from .models import *
# from email.mime import application
from rest_framework import serializers
# from .models import *
class UserSerializer(serializers.ModelSerializer):
    date_joined = serializers.ReadOnlyField()

    class Meta(object):
        model = User
        fields = ('id', 'email', 'first_name', 'last_name',
                  'password')
        extra_kwargs = {'password': {'write_only': True}}


class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model=Application
        fields='__all__'



class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # Assuming User is your Django User model
        fields ='__all__' #['id', 'email', 'application_id']  # Include the fields you want in the response



from django.conf import settings

###########_______________________This middle ware return the correct value______________________________________
# from rest_framework import serializers
# from datetime import timedelta
# from django.conf import settings
# from .models import User
# from django.utils import timezone
# from rest_framework_simplejwt.tokens import OutstandingToken

# class UserLoginActivitySerializer(serializers.ModelSerializer):
#     estimated_logout = serializers.SerializerMethodField()

#     class Meta:
#         model = User
#         fields = [
#             'email',
#             'first_name',
#             'last_name',
#             'last_login',
#             'logout',
#             'estimated_logout'
#         ]

#     def get_estimated_logout(self, obj):
#         session_duration = timedelta(seconds=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())

#         # Calculate logout time based on token expiration
#         try:
#             outstanding_tokens = OutstandingToken.objects.filter(user=obj)
#             for token in outstanding_tokens:
#                 if token.created_at + session_duration > timezone.now():
#                     return token.created_at + session_duration
#         except OutstandingToken.DoesNotExist:
#             pass
#         return obj.last_login + session_duration




# class UserLoginActivitySerializer(serializers.ModelSerializer):
#     estimated_logout = serializers.SerializerMethodField()

#     class Meta:
#         model = User
#         fields = ['email','first_name','last_name','last_login','logout','estimated_logout','is_active'
#         ]
#     def get_estimated_logout(self, obj):
#         session_duration = timedelta(seconds=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())
#         return obj.last_login + session_duration

from rest_framework import serializers
from .models import User, UserActivityLog
from datetime import timedelta
from django.conf import settings

class UserActivityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserActivityLog
        fields = ['id', 'email', 'ip_address', 'user_agent', 'created_at', 'logout_time', 'attempt_name']

class UserLoginActivitySerializer(serializers.ModelSerializer):
    estimated_logout = serializers.SerializerMethodField()
    activity_logs = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'last_login', 'logout', 'estimated_logout', 'is_active', 'activity_logs']

    def get_estimated_logout(self, obj):
        session_duration = timedelta(seconds=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())
        return obj.last_login + session_duration

    def get_activity_logs(self, obj):
        logs = UserActivityLog.objects.filter(user=obj).order_by('-created_at')
        return UserActivityLogSerializer(logs, many=True).data


#######___________________This is the section of___________________________________________________________________

# # serializers.py
from rest_framework import serializers
from .meetingmodels import HiringManagerAvailability

# class UserAvailabilitySerializer(serializers.ModelSerializer):
#     class Meta:
#         model = HiringManagerAvailability
#         fields = ['user', 'application', 'day_of_week', 'start_time', 'end_time','block_time', 'is_unavailable']

#     def validate(self, attrs):
#         # Ensure start_time is before end_time
#         if attrs['start_time'] >= attrs['end_time']:
#             raise serializers.ValidationError("start_time must be before end_time.")

#         # Check for overlapping times
#         existing_availability = HiringManagerAvailability.objects.filter(
#             user=attrs['user'],
#             application=attrs['application'],
#             day_of_week=attrs['day_of_week']
#         )

#         for availability in existing_availability:
#             if (attrs['start_time'] < availability.end_time and attrs['end_time'] > availability.start_time):
#                 raise serializers.ValidationError("The selected time overlaps with existing availability.")

#         return attrs


from rest_framework import serializers
from .meetingmodels import HiringManagerAvailability
from datetime import timedelta

class UserAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HiringManagerAvailability
        fields = ['user', 'application', 'day_of_week', 'start_time', 'end_time', 'is_unavailable']

    def validate(self, attrs):
        # Ensure start_time is before end_time
        if attrs['start_time'] >= attrs['end_time']:
            raise serializers.ValidationError("start_time must be before end_time.")

        # Check for overlapping times
        existing_availability = HiringManagerAvailability.objects.filter(
            user=attrs['user'],
            application=attrs['application'],
            day_of_week=attrs['day_of_week']
        )

        for availability in existing_availability:
            if (attrs['start_time'] < availability.end_time and attrs['end_time'] > availability.start_time):
                raise serializers.ValidationError("The selected time overlaps with existing availability.")

        return attrs

    def create(self, validated_data):
        # Calculate the block_time as the difference between end_time and start_time
        validated_data['block_time'] = timedelta(
            hours=validated_data['end_time'].hour,
            minutes=validated_data['end_time'].minute,
            seconds=validated_data['end_time'].second
        ) - timedelta(
            hours=validated_data['start_time'].hour,
            minutes=validated_data['start_time'].minute,
            seconds=validated_data['start_time'].second
        )

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Calculate the block_time during update
        validated_data['block_time'] = timedelta(
            hours=validated_data['end_time'].hour,
            minutes=validated_data['end_time'].minute,
            seconds=validated_data['end_time'].second
        ) - timedelta(
            hours=validated_data['start_time'].hour,
            minutes=validated_data['start_time'].minute,
            seconds=validated_data['start_time'].second
        )

        return super().update(instance, validated_data)



