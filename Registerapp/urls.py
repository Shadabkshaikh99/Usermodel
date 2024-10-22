from django.urls import path
from .views import (
    RegisterView,
    LoginAPIView,
    ChangePasswordAPIView,
    PasswordResetRequestView,  
   PasswordResetConfirmView,
    OTPGenerateView,
    OTPVerifyView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('otp/generate/', OTPGenerateView.as_view(), name='otp-generate'),
    path('otp/verify/', OTPVerifyView.as_view(), name='otp-verify'),
]