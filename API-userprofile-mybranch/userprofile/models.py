from django.db import models

# Create your models here.

# ---------------- Authorization models -------------
from pyexpat import model
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid
from django.core.exceptions import ValidationError
from django.utils import timezone

from datetime import datetime, timedelta
# from botshreyasi_api.application.models import Application
from django.core.validators import RegexValidator

class UserManager(BaseUserManager):
    def create_user(self, email, username, name, application_id,first_name,last_name, password=None, password2=None, **extra_fields):
        user = self.model(
            email=self.normalize_email(email),
            username=username,
            name=name,
            application_id=application_id,
            first_name = first_name,
            last_name=last_name,
            **extra_fields
        )
        # user.
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, first_name,  last_name, phone, password=None):
        user = self.create_user(
            email=email,
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
        )
        user.is_admin = True
        user.is_staff = True
        user.name = f'{first_name} {last_name}'
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    mobile_no_regex = RegexValidator(
        regex=r'^\d{3,15}$',
        message="Mobile number must be between 3 and 15 digits."
    )
    # id=models.AutoField(primary_key=True,null=False)
    uid = models.CharField(max_length=200, default=uuid.uuid4, unique=True)
    role_id = models.IntegerField(null=True, blank=True)
    email = models.EmailField(null=False, max_length=100, unique=True)
    first_name = models.CharField(null=False, max_length=100)
    last_name = models.CharField(null=False, max_length=100, default='.')
    username = models.CharField(null=False, max_length=100)
    phone = models.CharField(null=True, unique=True,max_length=12)
    date_joined = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    name = models.CharField(null=False, max_length=100)
    gender = models.IntegerField(null=True)
    #profile_pic = models.CharField(null=True, blank=True, max_length=150)
    profile_pic = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    mobile_no = models.CharField(
        max_length=150, null=False, unique=True, default='1',validators=[mobile_no_regex],)
    dob = models.DateField(default='2022-08-12')
    # app_id = models.IntegerField(blank=False, null=False, default=0)
    # application = models.ForeignKey(Application, on_delete=models.CASCADE)
    application_id = models.IntegerField(default=1)
    manager = models.IntegerField(blank=True, null=True)
    short_name = models.CharField(null=False, max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    login_attempts = models.IntegerField(default=0)
    forget_password_attempts = models.IntegerField(default=0)
    account_locked = models.BooleanField(default=False)
    logout = models.DateTimeField(null=True, blank=True)#Add today 

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username','first_name', 'last_name', 'mobile_no', 'name']
    password = models.CharField(max_length=1024)

    objects = UserManager()

    def __str__(self):
        return self.email + ", " + self.first_name

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    def check_login_attempts(self):
        if self.login_attempts >= 3:
            self.account_locked = True
            self.save()
            return False
        return True
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.save()

    def reset_forget_password_attempts(self):
        self.forget_password_attempts = 0
        self.save()

    def lock_account(self):
        self.account_locked = True
        self.save()

    def unlock_account(self):
        self.account_locked = False
        self.save()
        
    # Extract first and last name from the full name on save
    def save(self, *args, **kwargs):
        if not self.first_name and not self.last_name and self.name:
            # Splitting full name into first_name and last_name
            parts = self.name.split(' ', 1)
            self.first_name = parts[0]
            if len(parts) > 1:
                self.last_name = parts[1]
            else:
                self.last_name = '.' 
        super().save(*args, **kwargs)  
    # Method to calculate the estimated logout time
    def get_estimated_logout_time(self):
        session_duration = timedelta(minutes=600)  # Adjust as per the token expiration setting
        if self.last_login:
            return self.last_login + session_duration
        return None

    # Method to check if the user is logged in on another device
    def is_logged_in_elsewhere(self):
        return UserActivityLog.objects.filter(user=self, logout_time__isnull=True).exists()  

    class Meta:
        managed = False
        db_table = 'users'
    

# ---- Authorization models (above) ----
class CandidateDetails(models.Model):
    country_code_validator = RegexValidator(
        regex=r'^\+\d{1,3}$',  # Example: +123
        message="Country code must be in the format '+123'."
    )
    mobile_no_validator = RegexValidator(
        regex=r'^\d{4,11}$',  # Example: 4 to 11 digits
        message="mobile_no number must be between 4 and 11 digits."
    )

    id = models.AutoField(primary_key=True)
    first_name = models.CharField(max_length=45, blank=True, null=True)
    middle_name = models.CharField(max_length=45, blank=True, null=True,)
    last_name = models.CharField(max_length=45, blank=True, null=True)
    candidate_name = models.CharField(max_length=191, blank=True, null=True)
    # mobile_no =  models.CharField(max_length=10, blank=False, null=False, unique=True)
    country_code =  models.CharField(
        max_length=4,
        validators=[country_code_validator],
        blank=False, null=False, default="+91"
    )
    mobile_no = models.CharField(
        max_length=11,
        validators=[mobile_no_validator],
        blank=False, null=False
    )
    email = models.EmailField(blank=False, null=False)
    application_id = models.IntegerField(default=1)
    pan_no = models.CharField(max_length=6, blank=True, null=True)
    aadharcard_number = models.IntegerField( blank=True, null=True)
    skill_set = models.CharField(max_length=445, blank=True, null=True)
    gender = models.IntegerField(blank=True, null=True)
    current_organization = models.CharField(max_length=90, blank=True, null=True)
    current_designation = models.CharField(max_length=90, blank=True, null=True)
    ovarall_experiance = models.CharField(max_length=90, blank=True, null=True)
    relevant_experiance = models.CharField(max_length=90, blank=True, null=True)
    qualification = models.CharField(max_length=100, blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    preferred_location = models.CharField(max_length=190, blank=True, null=True)
    address = models.CharField(max_length=100, blank=True, null=True)
    current_salary = models.CharField(max_length=100, blank=True, null=True)
    expected_salary = models.CharField(max_length=100, blank=True, null=True)
    notice_period = models.IntegerField(blank=True, null=True)
    remark = models.CharField(max_length=100, blank=True, null=True)
    industry_type = models.CharField(max_length=100, blank=True, null=True)
    functional_area = models.CharField(max_length=100, blank=True, null=True)
    dob = models.DateField(blank=True, null=True)
    # source = models.IntegerField(blank=True, null=True)
    resume = models.CharField(max_length=100, blank=True, null=True)
    cvhtml = models.TextField(blank=True, null=True)
    ip_address = models.CharField(max_length=100, blank=True, null=True)
    jobboard_url = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    pincode =  models.IntegerField(blank=True, null=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.email} - {self.mobile_no} - {self.application_id}"

    def save(self, *args, **kwargs):
        if self.candidate_name:
            self.first_name, self.middle_name, self.last_name = self.parse_candidate_name(self.candidate_name)

        elif self.first_name and self.last_name:
            self.candidate_name = self.generate_candidate_name(self.first_name, self.middle_name, self.last_name)

        super().save(*args, **kwargs)

    @staticmethod
    def parse_candidate_name(candidate_name):
        # Implement your own parsing logic here
        # Split candidate_name into first_name, middle_name, last_name
        # For example:
        parts = candidate_name.split()
        if len(parts) == 1:
            return parts[0], None, None
        elif len(parts) == 2:
            return parts[0], None, parts[1]
        elif len(parts) >= 3:
            return parts[0], parts[1], " ".join(parts[2:])

    @staticmethod
    def generate_candidate_name(first_name, middle_name, last_name):
        # Implement your own logic here to generate candidate_name
        # For example:
        if middle_name:
            return f"{first_name} {middle_name} {last_name}"
        else:
            return f"{first_name} {last_name}"

    def clean(self):
        super().clean()

        if self.country_code and self.mobile_no:
            country_code_details = {
                '+441': {'start': '7', 'length': 11},   # UK: starting number '7', 11-digit mobile_no numbers
                '+123': {'start': '9', 'length': 10},   # Example: starting number '9', 10-digit mobile_no numbers
                '+999': {'start': '6', 'length': 9},    # Example: starting number '6', 9-digit mobile_no numbers
                '+91': {'start': ['9', '7', '8', '6'], 'length': 10},  # India: starting numbers ['9', '7', '8', '6'], 10-digit mobile_no numbers
                '+92': {'start': '3', 'length': 11},    # Pakistan: starting number '3', 11-digit mobile_no numbers
                '+55': {'start': '9', 'length': 11},    # Brazil: starting number '9', 11-digit mobile_no numbers
                '+93': {'start': '7', 'length': 10},    # Afghanistan: starting number '7', 10-digit mobile_no numbers
                '+358': {'start': '4', 'length': [8, 9, 10]},  # Finland: starting number '4', mobile_no numbers can be 8, 9, or 10 digits
                '+213': {'start': '', 'length': 4},     # Algeria: no starting number, 4-digit mobile_no numbers
                # Add more country codes and details as needed
            }

            details = country_code_details.get(self.country_code, None)
            if details:
                expected_length = details['length']
                starting_numbers = details['start']
                if starting_numbers and not any(self.mobile_no.startswith(starting_number) for starting_number in starting_numbers):
                    raise ValidationError(
                        f"The mobile_no number does not match the expected format for the country code '{self.country_code}'."
                    )
                if isinstance(expected_length, list) and len(self.mobile_no) not in expected_length:
                    raise ValidationError(
                        f"The mobile_no number length does not match the expected length(s) for the country code '{self.country_code}'."
                    )
                if isinstance(expected_length, int) and len(self.mobile_no) != expected_length:
                    raise ValidationError(
                        f"The mobile_no number length does not match the expected length for the country code '{self.country_code}'."
                    )



    class Meta:
        managed = False
        db_table = 'candidate_details'
        unique_together = (('application_id', 'email','mobile_no'),)

from django.db import models
class Application(models.Model):
    application_name = models.CharField(max_length=255,blank=False,null=False,unique=True)
    application_address = models.TextField()
    is_ats=models.IntegerField()
    application_mobileno=models.CharField(max_length=100)
    license_start_date=models.DateField(auto_now_add=True)
    license_end_date=models.DateField()
    no_of_license=models.IntegerField(default=1)
    website=models.CharField(max_length=255)
    application_pan_no=models.CharField(max_length=150)
    application_gst_no=models.CharField(max_length=150)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    default_status_id=models.IntegerField()
    default_referrer_id=models.IntegerField()
    secret_key=models.CharField(max_length=255)
    term_and_condition=models.BooleanField(default=False)
    state_name=models.CharField(max_length=150)
    logo_url=models.CharField(max_length=150)
    is_active=models.BooleanField(default=False)
    can_call=models.BooleanField(default=False)
    disable_crowed_sourcing=models.BooleanField(default=False)
    application_about=models.TextField()
    call_port_allow=models.IntegerField(default=2)
    working_days=models.IntegerField(default=5)
    billing_name=models.CharField(max_length=150)

    class Meta:
        managed = False
        db_table = 'applications'



class ApplicationDefault(models.Model):
    default_status_id = models.IntegerField(default=1)#models.ForeignKey(CandidateStatus, on_delete=models.CASCADE,default=1 related_name='if_sourced')
    default_referrer_status_id = models.IntegerField(default=2)#models.ForeignKey(CandidateStatus, on_delete=models.CASCADE,default=1 related_name='if_refered')
    application=models.IntegerField(default=1)
    # application = models.ForeignKey(Application, on_delete=models.CASCADE, default=1)
    ip_address=models.CharField(blank=False,null=False,max_length=150, default='0.0.0.0')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    class Meta:
        managed = False
        db_table = 'application_defaults'




class EmailTemplates(models.Model):
    template_name = models.CharField(max_length=100, blank=False, null=False)
    # template_type = models.CharField(db_column='template_type', max_length=50, blank=False, null=False)  # Field name made lowercase.
    template_area = models.CharField(max_length=45, blank=False, null=False)
    subject = models.CharField(max_length=255)
    message = models.TextField(blank=False, null=False)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE, default=1, related_name='added_email_tempalate', db_column='added_by')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, default=1)
    # email_header_footer = models.ImageField(default=0)#models.ForeignKey(EmailHeaderFooter, on_delete=models.CASCADE, default=None, blank=True, null=True)
    sended_by = models.CharField(db_column='sended_by', default='passive', max_length=50, blank=False, null=False)
    sender_name = models.CharField(db_column='sender_name', default='Bot Shreyasi', max_length=50, blank=False, null=False)
    ip_address=models.CharField(blank=False,null=False,max_length=150, default='0.0.0.0')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    design = models.TextField(null=True,blank=True)

    class Meta:
        managed = False
        db_table = 'email_templates'


        
class EmailsLogs(models.Model):
    uid = models.CharField(max_length=200, default=uuid.uuid4, unique=True)
    sended_by = models.CharField(db_column='sended_by', default='noreply', max_length=50, blank=False, null=False)
    sended_to = models.EmailField(db_column='sended_to', max_length=50, blank=False, null=False)
    is_send = models.IntegerField(default=0) #models.ForeignKey(MessageStatus, db_column='is_send', on_delete=models.CASCADE, default=0, blank=True, null=True)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True,blank=True)
    message = models.TextField(blank=False, null=False)
    subject = models.CharField(max_length=500, null=True)
    # attachments_folder = models.CharField(max_length=1000, blank=True, null=True)
    attachment = models.CharField(max_length=500, blank=True,null=True)
    sended_cc = models.CharField(max_length=500, blank=True,null=True)
    sended_bcc = models.CharField(max_length=500, blank=True,null=True)
    sent_date = models.DateTimeField()
    to_be_sent_date = models.DateTimeField(blank=True,null=True)
    added_by = models.ForeignKey(User, on_delete=models.CASCADE, default=1, related_name='added_email_log', db_column='added_by')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, default=1,related_name='application_email_log')
    candidate= models.ForeignKey(CandidateDetails, on_delete=models.CASCADE, default=1)
    email_template= models.ForeignKey(EmailTemplates, on_delete=models.CASCADE, default=3)
    is_otp = models.IntegerField()
    ip_address=models.CharField(blank=False,null=False,max_length=150, default='0.0.0.0')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    sender_name = models.CharField(db_column='sender_name', default='Bot Shreyasi', max_length=50, blank=False, null=False)
    is_update = models.IntegerField(blank=True,null=True)
    # campaign_trigger_history = models.ForeignKey(TriggerActionCampaign, on_delete=models.SET_NULL, blank=True,null=True)
    # campaign_trigger = models.ForeignKey(ActionTrigger, on_delete=models.SET_NULL, blank=True,null=True)

    # ------>> 
    is_smtp = models.BooleanField(default=False)

    class Meta:
        managed = False
        db_table = 'email_logs'
        
        

# Create your models here.
class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True,default=9)
    id = models.BigAutoField(primary_key=True)
    email = models.CharField(max_length=200)
    password = models.CharField(max_length=400)
    is_successful = models.BooleanField(default=False)
    user_agent = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=45)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    attempt_name = models.CharField(max_length=255)

    # Method to update logout time
    def update_logout_time(self):
        self.logout_time = timezone.now()
        self.save()

    class Meta:
        managed = False
        db_table = 'activity_log'
        
        
        

