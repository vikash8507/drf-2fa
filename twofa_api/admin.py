from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from twofa_api.models import User, TwoFactorAuth

class TwoFactorAuthAdmin(admin.ModelAdmin):
    list_display = ["user", "mobile_otp", "email_otp", "mfa_otp"]

admin.site.register(User, UserAdmin)
admin.site.register(TwoFactorAuth, TwoFactorAuthAdmin)