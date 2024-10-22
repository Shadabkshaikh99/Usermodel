from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model, authenticate
import random
from django.conf import settings
import string
from .models import User, PasswordResetToken
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)  # For password confirmation
    verification_code = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password2', 'phone_number', 'verification_code']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('password2')
        validated_data['username'] = validated_data['email']  # Use email as username
        validated_data['password'] = make_password(validated_data['password'])  # Hash the password
        user = User.objects.create(**validated_data)
        
        # Send the verification code
        self.send_verification_code(user)
        return user

    def send_verification_code(self, user):
        verification_code = self.generate_verification_code()
        user.verification_code = verification_code
        user.save()

        formatted_phone_number = self.format_phone_number(user.phone_number)

        # Send the verification code via SMS using Twilio
        from twilio.rest import Client
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        try:
            message = client.messages.create(
                body=f'Your verification code is {verification_code}',
                from_=settings.TWILIO_PHONE_NUMBER,
                to=formatted_phone_number
            )
            print(f"Message sent: {message.sid}")  # Debugging output
        except Exception as e:
            print(f"Failed to send message: {e}")

    def format_phone_number(self, phone_number):
        """Format phone number to E.164 format."""
        return f"+91{phone_number}"  # Adjust as needed

    def generate_verification_code(self):
        """Generate a random 6-digit verification code."""
        return str(random.randint(100000, 999999))


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError("Invalid credentials.")
        return {'user': user}


class ChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)


    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data




class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Perform case-insensitive lookup for the email
        try:
            user = User.objects.get(email__iexact=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user is associated with this email.")
        return value


class PasswordResetVerifySerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['new_password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
    def validate_token(self, value):
        # Ensure the token is valid and associated with the email
        try:
            token_instance = PasswordResetToken.objects.get(token=value)
            if not token_instance.is_valid():
                raise serializers.ValidationError("Token has expired.")
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Invalid token.")
        return value


from rest_framework import serializers

class OTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Add any custom email validation logic if needed
        return value

class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)

    def validate_otp_code(self, value):
        # Ensure the OTP is exactly 6 digits long and numeric
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP code must be a 6-digit numeric value.")
        return value