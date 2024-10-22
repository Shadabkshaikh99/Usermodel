from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid

class User(AbstractUser):
    
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    email = models.EmailField(unique=True)  # Ensure the email is unique
    verification_code = models.CharField(max_length=6, blank=True, null=True)  # Field to store the code
    is_verified = models.BooleanField(default=False)  # Whether the phone number is verified

    def _str_(self):
        return self.username
    


class PasswordResetToken(models.Model):
     email = models.EmailField()
     token = models.CharField(max_length=255, unique=True)
     valid_until = models.DateTimeField()

     def is_valid(self):
        """Check if the token is still valid."""
        return self.valid_until >= timezone.now()

     def _str_(self):
        return f'Token for {self.email}'
    



class OTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()

    def is_valid(self):
        return timezone.now() <= self.valid_until