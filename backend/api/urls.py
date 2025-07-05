from django.urls import path, include
from .views import CheckUrlView

urlpatterns = [
    path('check_url/', CheckUrlView.as_view(), name='check_url'),
]
