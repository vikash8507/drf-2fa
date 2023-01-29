import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException
from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    email = models.EmailField(max_length=100, unique=True, db_index=True)
    phone = models.CharField(max_length=10, null=True, blank=True)
    country_code = models.CharField(max_length=5, null=True, blank=True)
    phone_verified = models.BooleanField("Phone Verified?", default=False)
    email_verified = models.BooleanField("Email Verified?", default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
    class Meta:
        unique_together = ("phone", "country_code",)

    def clean(self, *args, **kwargs):
        if (self.phone and not self.country_code) or (not self.phone and self.country_code):
            raise ValidationError("Country Code and Phone Number both required")
        if self.phone and self.country_code:
            try:
                number = phonenumbers.parse(f"{self.country_code}{self.phone}", None)
            except NumberParseException as e:
                raise ValidationError(str(e))
            if not phonenumbers.is_valid_number(number):
                raise ValidationError("Please enter correct country code and phone number")
        super(User, self).clean(*args, **kwargs)

    def __str__(self):
        return self.email


class TwoFactorAuth(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile_otp = models.BooleanField("Enable Mobile OTP", default=False)
    email_otp = models.BooleanField("Enable Email OTP", default=False)
    mfa_otp = models.BooleanField("Enable MFA OTP", default=False)
    create_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.email