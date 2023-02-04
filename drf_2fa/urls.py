from django.contrib import admin
from django.urls import path, include
from drf_2fa.api_doc_urls import api_doc_urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('twofa_api.urls')),
] + api_doc_urls
