from django.urls import path

from twofa_api.views import RegisterAPIView, LoginAPIView, EnableDesableOTP

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("enable-desable/", EnableDesableOTP.as_view(), name="enable-desable")
]
