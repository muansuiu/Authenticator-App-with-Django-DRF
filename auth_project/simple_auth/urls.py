from django.urls import path, include
from rest_framework import routers
from .views import RegisterView, LoginView, VerifyOTP, OwnerRegistrationView, ProtectedView, PasswordResetFormView, OwnerView

urlpatterns = [
    path('register', RegisterView.as_view()),
    path('register/owner', OwnerRegistrationView.as_view()),
    path('login', LoginView.as_view()),
    path('otp/verify', VerifyOTP.as_view()),
    path('protected', ProtectedView.as_view()),
    path('reset_password', PasswordResetFormView.as_view()),
    path('owner/show-all', OwnerView.as_view())
]


