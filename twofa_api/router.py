from django.urls import re_path
from rest_framework import routers


class AuthRouter(routers.DefaultRouter):
    """
    Router class that disables the PUT and DETAIL method.
    """
    def get_urls(self):
        urls = []

        for prefix, viewset, basename in self.registry:
            lookup = self.get_lookup_regex(viewset)
            routes = self.get_routes(viewset)

            for route in routes:

                mapping = self.get_method_map(viewset, route.mapping)
                if not mapping:
                    continue

                regex = route.url.format(
                    prefix=prefix,
                    lookup=lookup,
                    trailing_slash=self.trailing_slash
                )

                if not prefix and regex[:2] == '^/':
                    regex = '^' + regex[2:]

                initkwargs = route.initkwargs.copy()
                initkwargs.update({
                    'basename': basename,
                    'detail': route.detail,
                })

                view = viewset.as_view(mapping, **initkwargs)
                name = route.name.format(basename=basename)
                urls.append(re_path(regex, view, name=name))
        return urls