# File: backend/api/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import EmailOTP
from django.contrib.auth import authenticate

class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)



class RegisterWithOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    otp = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data['email']
        otp = data['otp']
        try:
            otp_entry = EmailOTP.objects.get(email=email)
        except EmailOTP.DoesNotExist:
            raise serializers.ValidationError("No OTP found for this email.")

        if otp_entry.otp != otp:
            raise serializers.ValidationError("Invalid OTP.")

        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        EmailOTP.objects.filter(email=validated_data['email']).delete()  # cleanup
        return user


class EmailLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(username=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError("Invalid credentials")
        data['user'] = user
        return data
