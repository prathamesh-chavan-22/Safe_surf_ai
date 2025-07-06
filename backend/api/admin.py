from django.contrib import admin
from .models import URLScanResult  # ✅ import your model

@admin.register(URLScanResult)
class URLScanResultAdmin(admin.ModelAdmin):
    list_display = ('url', 'classification', 'created_at')  # Optional: customize columns
    search_fields = ('url',)
    list_filter = ('classification', 'created_at')
