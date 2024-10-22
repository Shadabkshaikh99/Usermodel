from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from django.utils.decorators import method_decorator
from django.core.mail import send_mail
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned
from .models import User
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from datetime import timedelta
from .models import PasswordResetToken  # Assuming you have a model for storing tokens
from .serializers import PasswordResetRequestSerializer, PasswordResetVerifySerializer
import random
import string
from django.contrib.auth.tokens import default_token_generator
from .serializers import (
    UserSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetVerifySerializer
)


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        if User.objects.filter(email=email).exists():
            return Response({"message": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({"message": "Registered successfully"}, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordAPIView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            try:
                user = User.objects.get(email=email)
                user.set_password(password)
                user.save()
                return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            except MultipleObjectsReturned:
                return Response({"message": "Multiple users found. Please contact support."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            # Generate a random token for the password reset link
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            valid_until = timezone.now() + timedelta(hours=1)  # Token valid for 1 hour

            # Save the token to the database
            PasswordResetToken.objects.create(email=email, token=token, valid_until=valid_until)

            # Send password reset link to the user's email
            reset_link = f'http://yourdomain.com/reset-password/?token={token}'  # Adjust URL as needed
            try:
                send_mail(
                    subject='Password Reset Request',
                    message=f'Click the link to reset your password: {reset_link}',
                    from_email='anushinde847@gmail.com',  # Ensure this is your email
                    recipient_list=[email],
                    fail_silently=False,
                )
            except Exception as e:
                return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "Password reset link sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        # Get token and email from the request data
        token = request.data.get('token')
        email = request.data.get('email')

        try:
            # Check if the token is valid for the user
            token_instance = PasswordResetToken.objects.get(email=email, token=token)
            if not token_instance.is_valid():
                return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = PasswordResetVerifySerializer(data=request.data)
            if serializer.is_valid():
                user = User.objects.get(email=email)
                new_password = serializer.validated_data['new_password']
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except PasswordResetToken.DoesNotExist:
            return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import OTP
from .serializers import OTPRequestSerializer, OTPVerifySerializer
from datetime import timedelta
import random

class OTPGenerateView(APIView):
    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = str(random.randint(100000, 999999))
            valid_until = timezone.now() + timedelta(minutes=5)  # OTP valid for 5 minutes

            # Save OTP to the database
            otp_instance = OTP.objects.create(email=email, otp_code=otp_code, valid_until=valid_until)

            # Send OTP to the user's email
            try:
                send_mail(
                    subject='Your OTP Code',
                    message=f'Your OTP code is {otp_code}. It is valid for 5 minutes.',
                    from_email='kajalbhosale2405@gmail.com',  # Ensure this is your email
                    recipient_list=[email],
                    fail_silently=False,
                )
            except Exception as e:
                return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OTPVerifyView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']

            # Verify OTP
            try:
                otp_instance = OTP.objects.get(email=email, otp_code=otp_code)
                if otp_instance.is_valid():
                    return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "OTP expired."}, status=status.HTTP_400_BAD_REQUEST)
            except OTP.DoesNotExist:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)