from django.conf import settings
from django.core.signing import BadSignature

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:

    class MiddlewareMixin:
        """Dummy class not to break compatibility with django 1.8"""

        pass


from .pinning import pin_this_thread, unpin_this_thread


def pinning_cookie():
    """The name of the cookie that directs a request's reads to the master DB."""
    return getattr(settings, 'MULTIDB_PINNING_COOKIE', 'multidb_pin_writes')


def pinning_cookie_httponly():
    return getattr(settings, 'MULTIDB_PINNING_COOKIE_HTTPONLY', False)


def pinning_cookie_samesite():
    return getattr(settings, 'MULTIDB_PINNING_COOKIE_SAMESITE', 'Lax')


def pinning_cookie_secure():
    return getattr(settings, 'MULTIDB_PINNING_COOKIE_SECURE', False)


def pinning_seconds():
    """The number of seconds for which reads are directed to the master DB
    after a write.
    """
    return int(getattr(settings, 'MULTIDB_PINNING_SECONDS', 15))


READ_ONLY_METHODS = frozenset(['GET', 'TRACE', 'HEAD', 'OPTIONS'])


def pinning_cookie_salt():
    """Salt for signed cookies - configurable per deployment."""
    return getattr(settings, 'MULTIDB_PINNING_COOKIE_SALT', 'multidb_pinning')


class PinningRouterMiddleware(MiddlewareMixin):
    """Middleware to support the PinningReplicaRouter

    Attaches a cookie to a user agent who has just written, causing subsequent
    DB reads (for some period of time, hopefully exceeding replication lag)
    to be handled by the master.

    When the cookie is detected on a request, sets a thread-local to alert the
    DB router.

    """

    def process_request(self, request):
        """Set the thread's pinning flag according to the presence of the
        incoming signed cookie or write request method."""
        should_pin = False

        # Check for write request methods (always pin)
        if request.method not in READ_ONLY_METHODS:
            should_pin = True
        else:
            # Check for valid signed pinning cookie
            try:
                cookie_value = request.get_signed_cookie(
                    pinning_cookie(), default=None, salt=pinning_cookie_salt()
                )
                if cookie_value:
                    should_pin = True
            except (BadSignature, ValueError, TypeError):
                # Cookie was tampered with, malformed, or invalid - ignore it for security
                pass

        if should_pin:
            pin_this_thread()
        else:
            # In case the last request this thread served was pinned:
            unpin_this_thread()

    def process_response(self, request, response):
        """For write requests or explicit DB writes, set a signed pinning cookie.

        The signed cookie prevents users from forging pinning cookies to
        maliciously overload the primary database.

        """
        if request.method not in READ_ONLY_METHODS or getattr(
            response, '_db_write', False
        ):
            response.set_signed_cookie(
                pinning_cookie(),
                value='pinned',
                salt=pinning_cookie_salt(),
                max_age=pinning_seconds(),
                secure=pinning_cookie_secure(),
                httponly=pinning_cookie_httponly(),
                samesite=pinning_cookie_samesite(),
            )
        return response
