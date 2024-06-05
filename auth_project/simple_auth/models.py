import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator, EmailValidator, RegexValidator

email_validator = EmailValidator()
password_validator = MinLengthValidator(8, message='Password must be at least 8 characters.')

mobile_validator = RegexValidator(
        regex=r'^880\d{10}$',
        message='Mobile number should start with 880 and have 13 characters.',
        code='invalid_mobile'
    )

name_validator = RegexValidator(
        regex=r'^[A-Za-z ]+$',
        message='Only letters are allowed',
        code='invalid_name'
    )


# Create your models here.
class Users(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, validators=[name_validator])
    email = models.EmailField(unique=True, validators=[email_validator])
    password = models.CharField(max_length=100, validators=[password_validator])
    role = models.CharField(default='general')
    secret_key = models.CharField(max_length=255, null=True)
    otp_verified = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password', 'name']

    def __str__(self):
        return f"{self.name}"
