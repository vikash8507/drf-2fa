from phonenumbers.phonenumberutil import NumberParseException
import phonenumbers

from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model

from rest_framework.exceptions import ValidationError
from rest_framework import serializers

User = get_user_model()

class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    phone = serializers.CharField()
    country_code = serializers.CharField()

    def validate(self, attrs):
        password1 = attrs.get("password1")
        password2 = attrs.get("password2")
        if password1 != password2:
            raise ValidationError("Password mismatch")
        validate_password(password=password1)

        phone = attrs.get("phone")
        country_code = attrs.get("country_code")
        if (phone and not country_code) or (not phone and country_code):
            raise ValidationError("Country Code and Phone Number both required")
        if phone and country_code:
            try:
                number = phonenumbers.parse(f"{country_code}{phone}", None)
            except NumberParseException as e:
                raise ValidationError("Please enter correct country code and phone number")
            if not phonenumbers.is_valid_number(number):
                raise ValidationError("Please enter correct country code and phone number")
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create(**validated_data)
        user.set_password(raw_password=password)
        user.is_active = False
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        user = User.objects.filter(email=attrs["email"]).first()
        if user is None:
            raise ValidationError("Please enter correct email")
        if not user.check_password(attrs["password"]):
            raise ValidationError("Please enter correct credentials")
        return super().validate(attrs)

class AccessTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, attrs):
        user = User.objects.filter(email=attrs["email"]).first()
        if user is None:
            raise ValidationError("Please enter correct email")
        if not user.check_password(attrs["password"]):
            raise ValidationError("Please enter correct credentials")
        if not attrs.get("otp"):
            raise ValidationError("Please enter OTP")
        return super().validate(attrs)

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        if not attrs.get("refresh_token"):
            raise ValidationError("Wrong refresh token")
        return super().validate(attrs)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password1 = serializers.CharField()
    new_password2 = serializers.CharField()

    def validate_old_password(self, value):
        user = getattr(self.context.get("request"), "user", None)
        if user is None:
            raise serializers.ValidationError(_("Please authenticate yourself first!"))
        if not user.check_password(value):
            raise serializers.ValidationError(_("Wrong old password!"))
        return value
    
    def validate(self, attrs):
        old_pass = attrs.get("old_password")
        new_pass1 = attrs.get("new_password1")
        new_pass2 = attrs.get("new_password2")
        if old_pass == new_pass1:
            raise serializers.ValidationError(_("Old nad New password can't same!"))
        if new_pass2 != new_pass1:
            raise serializers.ValidationError(_("Password 1 and 2 must be same!"))
        return super().validate(attrs)

    def create(self, validated_data):
        new_pass = validated_data.get("new_password1")
        user = getattr(self.context.get("request"), "user", None)
        user.set_password(raw_password=new_pass)
        user.save()
        return user

class ResetPasswordSerializer(serializers.Serializer):
    pass


class ResetPasswordConfirmSerializer(serializers.Serializer):
    pass