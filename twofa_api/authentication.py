import jwt
from django.conf import settings
from rest_framework import exceptions
from django.contrib.auth import get_user_model
from django.middleware.csrf import CsrfViewMiddleware
from rest_framework.authentication import BaseAuthentication


User = get_user_model()
secret = getattr(settings, "JWT_SECRET", "e6212459c3b9d354e257215fd665429c185")
algorithm = getattr(settings, "JWT_ALGORITHM", "HS256")


class CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        return reason


class SafeJWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        authorization_heaader = request.headers.get('Authorization')

        if not authorization_heaader:
            return None
        try:
            access_token = authorization_heaader.split(' ')[1]
            payload = jwt.decode(access_token, secret, algorithms=[algorithm])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Access Token Expired!')
        except IndexError:
            raise exceptions.AuthenticationFailed('Token Prefix Missing!')

        try:
            user = User.objects.get(id=payload.get('user_id'))
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('Wrong Token!')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User is not active!')

        # self.enforce_csrf(request)
        return user, None

    def enforce_csrf(self, request):
        check = CSRFCheck()
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)
