from django.db import models
from django.contrib.auth.models import User
import uuid

class EmailOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.email} - OTP: {self.otp}"

class URLScanResult(models.Model):
    url = models.URLField(unique=True)
    classification = models.CharField(max_length=20)
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} => {self.classification}"
