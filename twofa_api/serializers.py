from phonenumbers.phonenumberutil import NumberParseException
import phonenumbers

from django.contrib.auth.password_validation import validate_password
from django.utils.http import urlsafe_base64_encode as uid_encoder
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.core.mail import EmailMessage

from rest_framework.exceptions import ValidationError
from rest_framework import serializers

from twofa_api.utils import (
    validate_password, generate_email_verification,
    send_email, verify_email_token
)

User = get_user_model()


class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField()
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    phone = serializers.CharField()
    country_code = serializers.CharField()

    @classmethod
    def password_validates(cls, password1, password2):
        if password1 != password2:
            raise ValidationError(_("Password must be same!"))
        # if not validate_password(password1):
        #     raise ValidationError("Password must contains special chars, capital, small and digits and length 8 chars must be")

    @classmethod
    def _check_user_email_username_phone(cls, username=None, email=None, phone=None):
        # Validate unique username
        user = User.objects.filter(username=username).first()
        if user is not None:
            raise serializers.ValidationError(_("Username already exist!"))
        # Validate unique email
        user = User.objects.filter(email=email).first()
        if user is not None:
            raise serializers.ValidationError(_("Email already exist!"))
        # Validate unique phone
        user = User.objects.filter(phone=phone).first()
        if user is not None:
            raise serializers.ValidationError(_("Phone already exist!"))

    def validate(self, attrs):
        self.password_validates(attrs.get("password1"), attrs.get("password2"))
        self._check_user_email_username_phone(
            attrs.get("username"), attrs.get("email"), attrs.get("phone"))

        phone = attrs.get("phone")
        country_code = attrs.get("country_code")
        if (phone and not country_code) or (not phone and country_code):
            raise ValidationError(
                _("Country Code and Phone Number both required"))
        if phone and country_code:
            try:
                number = phonenumbers.parse(f"{country_code}{phone}", None)
            except NumberParseException as e:
                raise ValidationError(
                    _("Please enter correct country code and phone number"))
            if not phonenumbers.is_valid_number(number):
                raise ValidationError(
                    _("Please enter correct country code and phone number"))
        return super().validate(attrs)

    def create(self, validated_data):
        password1 = validated_data.pop("password1")
        validated_data.pop("password2")

        user = User.objects.create(**validated_data)
        user.set_password(raw_password=password1)
        user.is_active = False
        user.email_verified = False
        user.phone_verified = False
        user.save()

        token = generate_email_verification(user)
        uid = uid_encoder(force_bytes(user.pk))
        send_email(
            message=f"Token: {token}, UID: {uid}",
            subject="Email Verification mail",
            to=user.email
        )
        return user


class ResendVerifyLinkSerializer(serializers.Serializer):
    email = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get("email")
        user = User.objects.filter(email=email).first()
        if user is None:
            raise serializers.ValidationError(_("Email does not exist!"))
        print(user.email_verified)
        if user.email_verified:
            raise serializers.ValidationError(
                _("Email already verified! If you have any issue in login then contact with admin!"))
        attrs.update({
            "user": user
        })
        return super().validate(attrs)

    def create(self, validated_data):
        user = validated_data.get("user")
        token = generate_email_verification(user)
        uid = uid_encoder(force_bytes(user.pk))
        send_email(
            message=f"Token: {token}, UID: {uid}",
            subject="Email Verification mail",
            to=user.email
        )
        return user


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField()
    uid = serializers.CharField()

    def validate(self, attrs):
        uid = attrs.get("uid")
        token = attrs.get("token")
        if not uid or not token:
            raise serializers.ValidationError(_("UID or Token missing"))

        try:
            uid = force_str(uid_decoder(attrs['uid']))
            user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, User.DoesNotExist):
            raise ValidationError({'uid': _('Invalid uid!')})

        user.is_active = True
        user.email_verified = True
        user.save()
        attrs.update({
            "user": user
        })
        return super().validate(attrs)

    def create(self, validated_data):
        user = validated_data.get("user")
        token = validated_data.get("token")

        success, _user = verify_email_token(token)
        if not success:
            raise serializers.ValidationError(
                _("Token is wrong or expire. Please resend and reverify it!"))
        if user.username != _user.username:
            raise serializers.ValidationError(_("Wrong Token!"))

        user.is_active = True
        user.email_verified = True
        user.phone_verified = False
        user.save()
        return user


class InitialLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    _user = None

    def validate(self, attrs):
        user = User.objects.filter(email=attrs["email"]).first()
        if user is None:
            raise ValidationError(_("Please enter correct email"))
        if not user.is_active:
            raise ValidationError(_("User is not active"))
        if not user.check_password(attrs["password"]):
            raise ValidationError(_("Please enter correct credentials"))
        self._user = user
        return attrs


class VerifyMobileSerializer(serializers.Serializer):
    otp = serializers.CharField()


class EnableDesableSerializer(serializers.Serializer):
    device = serializers.CharField()
    why = serializers.CharField()

    def validate(self, attrs):
        device = attrs.get("device")
        why = attrs.get("why")
        if device not in ("email", "phone", "mfa"):
            raise serializers.ValidationError(
                "Please select email or phone or mfa device")
        if why not in ("enable", "disable"):
            raise serializers.ValidationError(
                "Please select enable or disable")
        return super().validate(attrs)


class AccessTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, attrs):
        user = User.objects.filter(email=attrs["email"]).first()
        if user is None:
            raise ValidationError(_("Please enter correct email"))
        if not user.check_password(attrs["password"]):
            raise ValidationError(_("Please enter correct credentials"))
        if not attrs.get("otp"):
            raise ValidationError(_("Please enter OTP"))
        return super().validate(attrs)


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        if not attrs.get("refresh_token"):
            raise ValidationError(_("Wrong refresh token"))
        return super().validate(attrs)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password1 = serializers.CharField()
    new_password2 = serializers.CharField()

    def validate_old_password(self, value):
        user = getattr(self.context.get("request"), "user", None)
        if user is None:
            raise serializers.ValidationError(
                _("Please authenticate yourself first!"))
        if not user.check_password(value):
            raise serializers.ValidationError(_("Wrong old password!"))
        return value

    def validate(self, attrs):
        old_pass = attrs.get("old_password")
        new_pass1 = attrs.get("new_password1")
        new_pass2 = attrs.get("new_password2")
        if old_pass == new_pass1:
            raise serializers.ValidationError(
                _("Old nad New password can't same!"))
        if new_pass2 != new_pass1:
            raise serializers.ValidationError(
                _("Password 1 and 2 must be same!"))
        return super().validate(attrs)

    def create(self, validated_data):
        new_pass = validated_data.get("new_password1")
        user = getattr(self.context.get("request"), "user", None)
        user.set_password(raw_password=new_pass)
        user.save()
        return user


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    @classmethod
    def _check_user(cls, email):
        user = User.objects.filter(email=email).first()
        return user

    @classmethod
    def send_email(self, data):
        email = EmailMessage(
            "Password Reset Link",
            f"UID: {data.get('uid')}, Token: {data.get('token')}",
            'hello@udyself.com',
            [data.get("email")]
        )
        email.send()

    def validate(self, attrs):
        email = attrs.get("email")
        user = self._check_user(email)
        if not user:
            raise serializers.ValidationError(_("Email does not exist!"))
        token = default_token_generator.make_token(user)
        uid = uid_encoder(force_bytes(user.pk))
        attrs.update({
            "token": token,
            "uid": uid
        })
        return attrs

    def save(self, *args, **kwargs):
        data = dict(self.validated_data.items())
        self.send_email(data)


class ResetPasswordConfirmSerializer(serializers.Serializer):
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    @classmethod
    def password_validates(cls, password1, password2):
        if password1 != password2:
            raise ValidationError(_("Password must be same!"))
        if not validate_password(password1):
            raise ValidationError(
                _("Password must contain special chars, capital, small and digits"))

    def validate(self, attrs):
        self.password_validates(
            attrs.get("new_password1"), attrs.get("new_password2"))
        try:
            uid = force_str(uid_decoder(attrs['uid']))
            _user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, User.DoesNotExist):
            raise ValidationError({'uid': _('Invalid data!')})

        if not default_token_generator.check_token(_user, attrs.get("token")):
            raise ValidationError({'token': _('Token expire or invalid!')})

        attrs.update({
            "user": _user
        })
        return attrs

    def create(self, validated_data):
        new_pass = validated_data.get("new_password1")
        user = validated_data.get("user")
        user.set_password(raw_password=new_pass)
        user.save()
        return user
