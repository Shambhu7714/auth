# Generated by Django 3.2.14 on 2024-01-13 07:53

import django.core.validators
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uid', models.CharField(default=uuid.uuid4, max_length=200, unique=True)),
                ('role_id', models.IntegerField(blank=True, null=True)),
                ('email', models.EmailField(max_length=100, unique=True)),
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(default='.', max_length=100)),
                ('username', models.CharField(max_length=100)),
                ('phone', models.CharField(max_length=12, null=True, unique=True)),
                ('date_joined', models.DateTimeField(auto_now=True)),
                ('last_login', models.DateTimeField(auto_now=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_superuser', models.BooleanField(default=False)),
                ('name', models.CharField(max_length=100)),
                ('gender', models.IntegerField(null=True)),
                ('profile_pic', models.CharField(blank=True, max_length=150, null=True)),
                ('mobile_no', models.CharField(default='1', max_length=150, unique=True, validators=[django.core.validators.RegexValidator(message='Mobile number must be between 3 and 15 digits.', regex='^\\d{3,15}$')])),
                ('dob', models.DateField(default='2022-08-12')),
                ('application_id', models.IntegerField(default=1)),
                ('manager', models.IntegerField(blank=True, null=True)),
                ('short_name', models.CharField(max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('update_at', models.DateTimeField(auto_now=True)),
                ('login_attempts', models.IntegerField(default=0)),
                ('forget_password_attempts', models.IntegerField(default=0)),
                ('account_locked', models.BooleanField(default=False)),
                ('password', models.CharField(max_length=1024)),
            ],
            options={
                'db_table': 'users',
                'managed': False,
            },
        ),
    ]
