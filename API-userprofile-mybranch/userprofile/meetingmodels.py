from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
#from . models import Application,User
from userprofile.models import Application,User  # Import Application from models.py

# Days of the week choices
DAYS_OF_WEEK = [
    ('Mon', 'Monday'),
    ('Tue', 'Tuesday'),
    ('Wed', 'Wednesday'),
    ('Thu', 'Thursday'),
    ('Fri', 'Friday'),
    ('Sat', 'Saturday'),
    ('Sun', 'Sunday'),
]

class HiringManagerAvailability(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='availability')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='availabilities')
    day_of_week = models.CharField(max_length=3, choices=DAYS_OF_WEEK)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    is_unavailable = models.BooleanField(default=False)
    sync_calendar = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    block_time = models.CharField(null=True, blank=True) 
    class Meta:
        managed = True
        db_table = "hiring_manager_availability"

    def __str__(self):
        return f"{self.user.username} - {self.get_day_of_week_display()}"

    def set_availability(self, day_of_week, start_time=None, end_time=None, is_unavailable=False):
        self.day_of_week = day_of_week
        self.start_time = start_time
        self.end_time = end_time
        self.is_unavailable = is_unavailable
        self.save()

    def apply_to_all_days(self, start_time, end_time):
        for day, _ in DAYS_OF_WEEK:
            HiringManagerAvailability.objects.create(
                user=self.user,
                application=self.application,
                day_of_week=day,
                start_time=start_time,
                end_time=end_time,
                is_unavailable=False
            )

    def apply_to_weekdays(self, start_time, end_time):
        weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri']
        for day in weekdays:
            HiringManagerAvailability.objects.create(
                user=self.user,
                application=self.application,
                day_of_week=day,
                start_time=start_time,
                end_time=end_time,
                is_unavailable=False
            )

    def apply_to_weekends(self, start_time, end_time):
        weekends = ['Sat', 'Sun']
        for day in weekends:
            HiringManagerAvailability.objects.create(
                user=self.user,
                application=self.application,
                day_of_week=day,
                start_time=start_time,
                end_time=end_time,
                is_unavailable=False
            )
