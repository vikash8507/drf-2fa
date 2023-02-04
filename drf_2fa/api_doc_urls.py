from drf_yasg.views import get_schema_view
from rest_framework import permissions
from django.urls import re_path
from drf_yasg import openapi


schema_view = get_schema_view(
   openapi.Info(
      title="Auth API",
      default_version='v1',
      description="Two Step Authentications",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="vikash1998bscc@gmail.com"),
      license=openapi.License(name="NA"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

api_doc_urls = [
    re_path(r'^docs(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^docs/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^redocs/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
