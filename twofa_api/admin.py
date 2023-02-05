from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from twofa_api.models import User, TwoFactorAuth
from twofa_api.forms import CustomUserChangeForm

class CustomUserAdmin(UserAdmin):
    form = CustomUserChangeForm

    list_display = ["username", "phone", "email", "email_verified", "phone_verified"]

    fieldsets = UserAdmin.fieldsets + (
            (None, {"fields": ("phone", "country_code", "email_verified", "phone_verified",)}),
    )

class TwoFactorAuthAdmin(admin.ModelAdmin):

    list_display = ["user", "mobile_otp", "email_otp", "mfa_otp"]

admin.site.register(User, CustomUserAdmin)
admin.site.register(TwoFactorAuth, TwoFactorAuthAdmin)