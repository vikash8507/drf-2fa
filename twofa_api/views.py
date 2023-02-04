from rest_framework.decorators import (
    action, authentication_classes, 
    permission_classes
)
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework import authentication, permissions

from twofa_api.serializers import (
    RefreshTokenSerializer, ChangePasswordSerializer,
    UserSerializer, LoginSerializer, AccessTokenSerializer, 
    ResetPasswordSerializer, ResetPasswordConfirmSerializer
)
from twofa_api.models import TwoFactorAuth
from twofa_api.utils import send_email

class AuthAPIView(viewsets.GenericViewSet):
    
    def get_serializer_class(self):
        if self.action == "register":
            return UserSerializer
        elif self.action == "access_token":
            return AccessTokenSerializer
        elif self.action == "refresh_token":
            return RefreshTokenSerializer
        return LoginSerializer
    
    @action(detail=False, methods=["POST"], url_name="register")
    def register(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


    @action(detail=False, methods=["POST"], url_name="initial_login")
    def initial_login(self, request, *args, **kwargs):
        serializer = self.get_serializer_class()
        serializer.is_valid(raise_exception=True)
        send_email(serializer.data['email'], "OTP", "OTP is 873186")
        return Response({"msg": "Otp Send to your device"})

    @action(detail=False, methods=["POST"], url_name="access_token")
    def access_token(self, request, *args, **kwargs):
        serializer = self.get_serializer()
        serializer.is_valid(raise_exception=True)
        # send_email(serializer.email, "OTP", "OTP is 873186")
        return Response({"msg": "wait"})

    @action(detail=False, methods=["POST"], url_name="refresh_token")
    def refresh_token(self, request, *args, **kwargs):
        serializer = self.get_serializer()
        serializer.is_valid(raise_exception=True)
        # send_email(serializer.email, "OTP", "OTP is 873186")
        return Response({"msg": "wait"})

    @authentication_classes([authentication.TokenAuthentication, authentication.SessionAuthentication])
    @permission_classes([permissions.IsAuthenticated])
    @action(detail=False, methods=["POST"], url_name="refresh_token")
    def enable_desable_otp(self, request, *args, **kwargs):
        device = request.data.get("device")
        why = request.data.get("why")

        verify_device, message, status_code = self.verify_device_data(device=device, why=why)
        if verify_device and message and status_code:
            return Response(message, status=status_code)
        
        obj, created = TwoFactorAuth.objects.get_or_create(user=request.user)
        if created and why == "disable":
            obj.delete()
            return Response({"error": "Device is not enabled yet!"}, status=status.HTTP_400_BAD_REQUEST)

        if created:
            if device == "email":
                obj.email_otp = True
            elif device == "mobile":
                obj.mobile_otp == True
            else:
                obj.mfa_otp = True
            obj.save()
        else:
            if device == "email":
                obj.email_otp = True
                obj.mobile_otp, obj.mfa_otp = False, False
            elif device == "mobil":
                obj.email_otp, obj.mfa_otp = False, False
                obj.mobile_otp = True
            else:
                obj.email_otp, obj.mobile_otp = False, False
                obj.mfa_otp = True
            obj.save()
        return Response({"msg": f"Device succussfully {why}d!"})

    @staticmethod
    def verify_device_data(cls, device, why):
        if not device and not why:
            return {"error": "Please send device and why"}, status.HTTP_400_BAD_REQUEST
        if device not in ("email", "phone", "mfa"):
            return {"error": "Please select email or phone or mfa device"}, status.HTTP_400_BAD_REQUEST
        if why not in ("enable", "disable"):
            return {"error": "Please select enable or disable"}, status.HTTP_400_BAD_REQUEST
        return False, None, None

class PasswordAPIView(viewsets.GenericViewSet):
    
    def get_serializer_class(self):
        if self.action == "change_password":
            return ChangePasswordSerializer
        elif self.action == "reset_confirm_password":
            return ResetPasswordConfirmSerializer
        elif self.action == "reset_password":
            return ResetPasswordSerializer
    
    @action(detail=False, methods=["POST"], url_name="change_password")
    def change_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Password Changed!"}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["POST"], url_name="reset_password")
    def reset_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Password reset email send to your email."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["POST"], url_name="reset_confirm_password")
    def reset_confirm_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Password set with new password."}, status=status.HTTP_200_OK)