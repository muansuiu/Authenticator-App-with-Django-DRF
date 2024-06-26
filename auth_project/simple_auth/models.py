import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from utilities.utils import FieldValidators

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


# Create your models here.
class Users(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, validators=[FieldValidators.name_validator])
    email = models.EmailField(unique=True, validators=[FieldValidators.email_validator])
    password = models.CharField(max_length=100, validators=[FieldValidators.password_validator])
    role = models.CharField(default='general')
    secret_key = models.CharField(max_length=255, null=True)
    otp_verified = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password', 'name']

    objects = CustomUserManager()

