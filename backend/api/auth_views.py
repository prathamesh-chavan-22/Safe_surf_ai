# auth_views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail
import random
from .models import EmailOTP
from .serializers import (
    EmailSerializer, VerifyOTPSerializer,
    RegisterWithOTPSerializer, EmailLoginSerializer
)
from rest_framework.permissions import AllowAny, IsAuthenticated

# Generate and send OTP
class SendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = str(random.randint(100000, 999999))

            EmailOTP.objects.update_or_create(email=email, defaults={'otp': otp})
            send_mail(
                subject='Your OTP Code',
                message=f'Your OTP is: {otp}',
                from_email='no-reply@example.com',
                recipient_list=[email],
                fail_silently=False
            )
            return Response({"message": "OTP sent to email"}, status=200)
        return Response(serializer.errors, status=400)

# Verify OTP
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            try:
                record = EmailOTP.objects.get(email=email)
                if record.otp == otp:
                    return Response({"message": "OTP verified"}, status=200)
                return Response({"error": "Invalid OTP"}, status=400)
            except EmailOTP.DoesNotExist:
                return Response({"error": "No OTP found for this email"}, status=404)
        return Response(serializer.errors, status=400)

# Register after OTP verification
class RegisterWithOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterWithOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            if not EmailOTP.objects.filter(email=email).exists():
                return Response({"error": "Please verify OTP first"}, status=400)

            user = serializer.save()
            EmailOTP.objects.filter(email=email).delete()  # clear OTP
            return Response({"message": "User registered successfully"}, status=201)

        return Response(serializer.errors, status=400)

# Email login
class EmailLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                "token": token.key,
                "user_id": user.id,
                "email": user.email
            })
        return Response(serializer.errors, status=400)

# Logout
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        return Response({"message": "Logged out successfully"})
