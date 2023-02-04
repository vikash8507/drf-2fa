from django.urls import path, include

from twofa_api.views import LoginAPIView
from twofa_api.router import AuthRouter

router = AuthRouter()
router.register(r'', LoginAPIView, basename="auth-api")

urlpatterns = [
    path('', include(router.urls)),
]
