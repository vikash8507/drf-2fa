from django.contrib import admin

from twofa_api.models import User, TwoFactorAuth

class UserAdmin(admin.ModelAdmin):
    list_display = ["email", "is_active", "is_superuser"]

class TwoFactorAuthAdmin(admin.ModelAdmin):
    list_display = ["user__email", "mobile_otp", "email_otp", "mfa_otp"]

admin.site.register(User)
admin.site.register(TwoFactorAuth)