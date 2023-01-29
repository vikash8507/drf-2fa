import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model

from twofa_api.utils import send_email

User = get_user_model()

class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    phone = serializers.CharField()
    country_code = serializers.CharField()

    def validate(self, attrs):
        password = attrs.get("password")
        validate_password(password=password)

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
        validate_password(attrs["password"])
        
        user = User.objects.filter(email=attrs["email"]).first()
        if user is None:
            raise ValidationError("Please enter correct email")
        if not user.check_password(attrs["password"]):
            raise ValidationError("Please enter correct credentials")

        send_email(attrs["email"], "OTP", "Otp is 939293")
        return super().validate(attrs)