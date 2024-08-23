from django.shortcuts import render

# from application.serializer import ApplicationSerializer
from django.conf import settings
import json
from django.db import connections, connection
from userprofile.models import User
from django.http import JsonResponse
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from userprofile.models import Application
# with connections['my_db_alias'].cursor() as cursor:
# from url_shortner.models import UrlShortners
# from url_shortner.serializers import UrlShortnersSerializer
import re
import random
import secrets
# from django.contrib.sites.models import Site

# from activity_log.serializers import ActivityLogSerializer


# --- activity_log app ---
# serializer
from rest_framework import serializers
# from .models import ActivityLog

# models.py
from django.db import models

# Create your models here.

# def checkToken(data):
#         print(",...........................................................>")
#         JWT_authenticator = JWTAuthentication()
#         response = JWT_authenticator.authenticate(data)
#         return response

def GetApplication(application_id):
    try:
        application = ApplicationSerializer(
            Application.objects.get(id=application_id)).data
    except:
        print('No data Found')
    return application

class ActivityLog(models.Model):

    email = models.CharField(max_length=200, null=True)
    password = models.CharField(max_length=400, null=True)
    is_successful = models.BooleanField(null=True)

    user_agent = models.CharField(max_length=255, null=True)
    ip_address = models.CharField(max_length=45, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)  # <- is useful here?
    attempt_name = models.CharField(max_length=255, null=True)
    # application = models.ForeignKey(Application, on_delete=models.CASCADE)
    # user = models.ForeignKey(CandidateDetails, on_delete=models.CASCADE)
    # otp = models.IntegerField(null=True)
    # url = models.CharField(max_length=100, null=True)
    # number_of_attempts = models.IntegerField(null=True)
    logout_time = models.DateTimeField(null=True)


    class Meta:
        managed = True
        db_table = "activity_log"



class ActivityLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = ActivityLog
        fields = "__all__"

def log_activity(data=dict()):

    activityLogSerializer = ActivityLogSerializer(data=data)
    if activityLogSerializer.is_valid():
        activityLogSerializer.save()
    else:
        print("WARNING: ", activityLogSerializer.errors)

# def getUser():
#     user = vars(get_current_authenticated_user())
#     del user['_state']
#     return user


# def GetUserID():
#     print("---------------------------------------------------------------------------------------")
#     print(get_current_authenticated_user())
#     print("---------------------------------------------------------------------------------------")
#     user_id = get_current_authenticated_user().id
#     return user_id




# def GetApplication():
#     application_id = get_current_authenticated_user().application_id
#     try:
#         application = ApplicationSerializer(
#             Application.objects.get(id=application_id)).data
#     except:
#         print('No data Found')
#     return application


# def GetAppID(data):
#     test , token = data
#     print(test)
#     print(f"user_id-------->{test.application_id}")
#     return test.id


def MysqlCombineRowColumn(DBRow, DBcursor):
    DBColumn = [column[0]
                for column in DBcursor.description]
    DBResponse = []
    for event in DBRow:
        DBResponse.append(dict(zip(DBColumn, event)))
    return DBResponse


def MysqlCombineModelsRowColumn(RowName, ModelFields, ModelData):
    ColumnNames = [field.name for field in ModelFields if field.name != 'id']
    MergedData = {'Row Name': RowName, }
    for column in ColumnNames:
        if hasattr(ModelData, column):
            MergedData[column] = getattr(ModelData, column)
        else:
            MergedData[column] = None
    return MergedData


def can_be_int(value):
    try:
        int(value)
        return True
    except (ValueError, TypeError):
        return False


def GetStoreProcedureData(functions, params):
    # DBcursor = connections["mysqlslave"].cursor()
    with connections["mysqlslave"].cursor() as DBcursor:
        DBcursor.callproc(functions, params)
        DBRow = DBcursor.fetchall()
        return MysqlCombineRowColumn(DBRow, DBcursor)


def GetQueryData(DBqueary):
    # DBcursor = connections["mysqlslave"].cursor()
    with connections["mysqlslave"].cursor() as DBcursor:
        DBcursor.execute(DBqueary)
        DBRow = DBcursor.fetchall()
        return MysqlCombineRowColumn(DBRow, DBcursor)
    # DBColumn = [column[0]
    #     for column in DBcursor.description]
    # DBResponse = []
    # for event in DBRow:
    #     DBResponse.append(dict(zip(DBColumn, event)))
    # return DBResponse


def GetChild(application_id, self_id):
    all_users = User.objects.filter(application_id=application_id).order_by(
        'manager').values('id', 'manager')
    all_users_after = [dict(user) for user in all_users]
    all_role = {}
    for user in all_users_after:
        all_child = get_all_child(all_users_after, user['id'])
        all_role[user['id']] = all_child
    set_to_parent(all_role)
    return all_role[int(self_id)]


# def GetChildWithSelf(app_id, user_id, is_comma_separated=False):

#     # Define your get_child function accordingly
#     childs = GetChild(app_id, user_id)
#     childs.append(user_id)
#     if is_comma_separated:
#         return ','.join(map(str, childs))
#     else:
#         return childs


def get_all_child(arr, id):
    all_id = []
    for user in arr:
        if user['manager'] == id and user['id']:
            all_id.append(user['id'])
    return all_id


def set_all_data_to_key(all_ids, all_role):
    all_ids_temp = all_ids.copy()
    for index, value in enumerate(all_ids_temp):
        data = all_role[value]
        for val in data:
            if val not in all_ids:
                all_ids.append(val)
    return all_ids


def set_to_parent(all_role):
    for k1, v1 in all_role.items():
        current_id = k1
        for k, v in all_role.items():
            all_ids = all_role[current_id]
            # Pass all_role as an argument
            all_ids = set_all_data_to_key(all_ids, all_role)
            all_role[current_id] = all_ids


def StrReplace(string, array):
    for key, value in array.items():
        if isinstance(value, str):
            string = string.replace(f"[{key}]", value)
    return string


# def prepare_message(data, template):
#     print(data)
#     print(template)
#     for key, value in data:
#         template = template.replace(f'{{{key}}}', str(value))
#     return template
def prepare_message(data, template):
    for item in data:
        for key, value in item.items():
            template = template.replace(f'{{{key}}}', str(value))
    return template


# def generate_key(string, data):
#     # pattern = r'\[{(.*?)}\]'
#     print("genrate key ---------------->")
#     pattern = r'\*(.*?)\*'
#     print(string)
#     template = re.findall(pattern, string)
#     unique_template = list(set(template))
#     id=None
#     for link in unique_template:
#         random_key =  secrets.token_urlsafe(3)
#         chat_key =  secrets.token_urlsafe(32)
#         old_url = settings.SELF_DOMAIN + link
#         new_url = "b0t.in/"+ random_key
#         user_id = data[0].get('user_id', None)
#         Shortnersdata = {
#                     'url_key':random_key,
#                     'old_url':old_url,
#                     'chat_key':chat_key,
#                     'url_name' : "test",
#                     'user': user_id,
#                     'application' : data[0].get('application_id', None),
#                     'candidate' : data[0].get('candidate_id', None),
#                     'campaign_trigger' : data[0].get('campaign_trigger_id', None),
#                     'campaign' : data[0].get('campaign_id', None),
#         }
#         print(Shortnersdata)
#         ShortnersSerializer = UrlShortnersSerializer(data=Shortnersdata)
#         if ShortnersSerializer.is_valid():
#             UrlShortners_instance = ShortnersSerializer.save()
#             id = UrlShortners_instance.id
#         else:
#             print(ShortnersSerializer.errors)
#         string = string.replace(f"**{link}**", new_url)
#         id = UrlShortners_instance.id
#     data = {'template': string, 'urlshortner_id': id}
#     print(string)
#     return data



# def generate_key(string, data,url_for):
#     # Define the pattern to match text between '*'
#     pattern = r'\*(.*?)\*'
#     unique_template = list(set(re.findall(pattern, string)))
#     ids =[]
#     for link in unique_template:
#         random_key = secrets.token_urlsafe(3)
#         chat_key = secrets.token_urlsafe(32)
#         old_url = settings.SELF_DOMAIN + link
#         new_url = "b0t.in/" + random_key
        
#         # Retrieve values from 'data' dictionary
#         user_id = data[0]['user_id']
#         application_id = data[0]['application_id']
#         candidate_id = data[0]['candidate_id']
#         campaign_trigger_id = data[0]['campaign_trigger_id']
#         campaign_id = data[0]['campaign_id']
#         campaign_trigger_history_id = data[0]['campaign_trigger_history_id']
        
#         # Create a dictionary for UrlShortners data
#         urlshortner_data = {
#             'url_key': random_key,
#             'old_url': old_url,
#             'chat_key': chat_key,
#             'url_name': "test",
#             'user': user_id,
#             'application': application_id,
#             'candidate': candidate_id,
#             'campaign_trigger': campaign_trigger_id,
#             'campaign_trigger_history': campaign_trigger_history_id,
#             'campaign': campaign_id,
#             'url_for': url_for
#         }

#         # Serialize and save the UrlShortners data
#         urlshortner_serializer = UrlShortnersSerializer(data=urlshortner_data)
#         if urlshortner_serializer.is_valid():
#             UrlShortners_instance = urlshortner_serializer.save()
#             ids.append(UrlShortners_instance.id)
#         else:
#             print(urlshortner_serializer.errors)

#         # Replace the link in the 'string' with the new URL
#         string = string.replace(f"*{link}*", new_url)

#     return {'template': string, 'urlshortner_id': ids}


def CalculateDatetimeInterval(value, unit):
    if unit == 'i':
        return timedelta(minutes=value)
    elif unit == 'h':
        return timedelta(hours=value)
    elif unit == 'd':
        return timedelta(days=value)
    elif unit == 'm':
        return relativedelta(months=value)
    elif unit == 'y':
        # Approximate year interval (not accounting for leap years)
        return timedelta(days=365 * value)
    else:
        raise ValueError(
            "Invalid unit. Use 'i' for minutes, 'h' for hours, 'd' for days, 'm' for months, or 'y' for years.")

from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
# from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.authentication import JWTAuthentication
from userprofile.serializers import ApplicationSerializer
from . models import *

# def getUserId(data):
#         JWT_authenticator = JWTAuthentication()
#         print("..............................................................................#######")
#         response = JWT_authenticator.authenticate(data)
#         print(response)
#         if response is not None:
#             user , token = response
#             print("user decoded from token is:", user, user.email)
#             return user.id
#         else:
#             print("no token is provided in the header or the header is missing")
            
        
# def getUserId(data):
#         test , token = data
#         print(test)
#         print(f"user_id-------->{test.id}")
#         return test.id
        # JWT_authenticator = JWTAuthentication()
        # print("..............................................................................#######")
        # response = JWT_authenticator.authenticate(data)
        # print(response)
        # if response is not None:
        #     user , token = response
        #     print("user decoded from token is:", user, user.email)
        #     return user.application_id
        # else:
        #     print("no token is provided in the header or the header is missing")
            
        