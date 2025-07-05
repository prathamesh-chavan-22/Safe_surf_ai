from django.urls import path
from .views import Calculate_Suspicion


urlpatterns = [
    path('check_url/', Calculate_Suspicion.as_view(), name='check_url'),
]