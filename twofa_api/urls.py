from django.urls import path, include

from twofa_api.views import AuthAPIView, PasswordAPIView, RegisterVerifyEmailAPIView
from twofa_api.router import AuthRouter

router = AuthRouter()
router.register(r'auth', AuthAPIView, basename="auth-api")
router.register(r'register', RegisterVerifyEmailAPIView, basename="auth-verify-api")
router.register(r'password', PasswordAPIView, basename="auth-password-api")

urlpatterns = [
    path('', include(router.urls)),
]
