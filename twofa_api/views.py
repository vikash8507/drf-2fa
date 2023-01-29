from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import permission_classes, authentication_classes
from rest_framework import authentication, permissions

from twofa_api.serializers import UserSerializer, LoginSerializer
from twofa_api.models import TwoFactorAuth

class RegisterAPIView(APIView):

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class LoginAPIView(APIView):
    
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"msg": "wait"})

class EnableDesableOTP(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [authentication.SessionAuthentication]

    def post(self, request, *args, **kwargs):
        device = request.data.get("device")
        why = request.data.get("why")

        if not device and not why:
            return Response({"error": "Please send device and why"}, status=status.HTTP_400_BAD_REQUEST)
        if device not in ("email", "phone", "mfa"):
            return Response({"error": "Please select email or phone or mfa device"}, status=status.HTTP_400_BAD_REQUEST)
        if why not in ("enable", "disable"):
            return Response({"error": "Please select enable or disable"}, status=status.HTTP_400_BAD_REQUEST)
        
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
                obj.mobile_otp = False
                obj.mfa_otp = False
            elif device == "mobil":
                obj.email_otp = False
                obj.mobile_otp = True
                obj.mfa_otp = False
            else:
                obj.email_otp = False
                obj.mobile_otp = False
                obj.mfa_otp = True
            obj.save()
        return Response({"msg": f"Device succussfully {why}d!"})