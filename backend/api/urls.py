from django.urls import path
from .auth_views import (
    SendOTPView, VerifyOTPView, RegisterWithOTPView,
    EmailLoginView, LogoutView
)
from .views import Calculate_Suspicion, RedirectAnalyzer

urlpatterns = [
    path('send-otp/', SendOTPView.as_view()),
    path('verify-otp/', VerifyOTPView.as_view()),
    path('register/', RegisterWithOTPView.as_view()),
    path('login/', EmailLoginView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('check-url/', Calculate_Suspicion.as_view()),
    path("redirect-analyzer/", RedirectAnalyzer.as_view(), name="redirect-analyzer"),
]
