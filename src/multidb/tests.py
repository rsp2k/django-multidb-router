import warnings
from threading import Lock, Thread

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signing import BadSignature
from django.http import HttpRequest, HttpResponse
from django.test import TestCase
from django.test.utils import override_settings

try:
    from unittest import mock
except ImportError:
    from unittest import mock

# For deprecation tests
import multidb
import multidb.pinning
from multidb import DEFAULT_DB_ALIAS, PinningReplicaRouter, ReplicaRouter, get_replica
from multidb.middleware import (
    PinningRouterMiddleware,
    pinning_cookie,
    pinning_cookie_httponly,
    pinning_cookie_samesite,
    pinning_cookie_secure,
    pinning_seconds,
)
from multidb.pinning import (
    db_write,
    pin_this_thread,
    this_thread_is_pinned,
    unpin_this_thread,
    use_primary_db,
)


class UnpinningTestCase(TestCase):
    """Test case that unpins the thread on tearDown"""

    def tearDown(self):
        unpin_this_thread()


class ReplicaRouterTests(TestCase):
    def test_db_for_read(self):
        # Both should return valid replica databases (may differ due to caching)
        router_result = ReplicaRouter().db_for_read(None)
        get_replica_result = get_replica()

        # Both should be replica databases (not necessarily the same due to round-robin)
        expected_replicas = getattr(settings, 'REPLICA_DATABASES', ['replica'])
        self.assertIn(router_result, expected_replicas)
        self.assertIn(get_replica_result, expected_replicas)

    def test_db_for_write(self):
        self.assertEqual(ReplicaRouter().db_for_write(None), DEFAULT_DB_ALIAS)

    def test_allow_syncdb(self):
        router = ReplicaRouter()
        assert router.allow_syncdb(DEFAULT_DB_ALIAS, None)
        assert not router.allow_syncdb(get_replica(), None)

    def test_allow_migrate(self):
        router = ReplicaRouter()
        assert router.allow_migrate(DEFAULT_DB_ALIAS, 'dummy')
        assert not router.allow_migrate(get_replica(), 'dummy')


class SettingsTests(TestCase):
    """Tests for default settings."""

    def test_defaults(self):
        """Check that the cookie name has the right default."""
        self.assertEqual(pinning_cookie(), 'multidb_pin_writes')
        self.assertEqual(pinning_seconds(), 15)
        self.assertEqual(pinning_cookie_secure(), False)
        self.assertEqual(pinning_cookie_httponly(), False)
        self.assertEqual(pinning_cookie_samesite(), 'Lax')

    @override_settings(MULTIDB_PINNING_COOKIE='override_pin_writes')
    @override_settings(MULTIDB_PINNING_SECONDS=60)
    @override_settings(MULTIDB_PINNING_COOKIE_SECURE=True)
    @override_settings(MULTIDB_PINNING_COOKIE_HTTPONLY=True)
    @override_settings(MULTIDB_PINNING_COOKIE_SAMESITE='Strict')
    def test_overrides(self):
        self.assertEqual(pinning_cookie(), 'override_pin_writes')
        self.assertEqual(pinning_seconds(), 60)
        self.assertEqual(pinning_cookie_secure(), True)
        self.assertEqual(pinning_cookie_httponly(), True)
        self.assertEqual(pinning_cookie_samesite(), 'Strict')


class PinningTests(UnpinningTestCase):
    """Tests for "pinning" functionality, above and beyond what's inherited
    from ReplicaRouter."""

    def test_pinning_encapsulation(self):
        """Check the pinning getters and setters."""
        assert not this_thread_is_pinned(), (
            'Thread started out pinned or this_thread_is_pinned() is broken.'
        )

        pin_this_thread()
        assert this_thread_is_pinned(), "pin_this_thread() didn't pin the thread."

        unpin_this_thread()
        assert not this_thread_is_pinned(), (
            'Thread remained pinned after unpin_this_thread().'
        )

    def test_pinned_reads(self):
        """Test PinningReplicaRouter.db_for_read() when pinned and when
        not."""
        router = PinningReplicaRouter()

        self.assertEqual(router.db_for_read(None), get_replica())

        pin_this_thread()
        self.assertEqual(router.db_for_read(None), DEFAULT_DB_ALIAS)

    def test_db_write_decorator(self):
        def read_view(req):
            self.assertEqual(router.db_for_read(None), get_replica())
            return HttpResponse()

        @db_write
        def write_view(req):
            self.assertEqual(router.db_for_read(None), DEFAULT_DB_ALIAS)
            return HttpResponse()

        router = PinningReplicaRouter()
        self.assertEqual(router.db_for_read(None), get_replica())
        write_view(HttpRequest())
        read_view(HttpRequest())


class MiddlewareTests(UnpinningTestCase):
    """Tests for the middleware that supports pinning"""

    def setUp(self):
        super().setUp()

        # Django 4.0 requires response as an arg
        # https://stackoverflow.com/questions/62944755/how-to-unittest-new-style-django-middleware
        get_response = mock.MagicMock()

        # Every test uses these, so they're okay as attrs.
        self.request = HttpRequest()
        self.middleware = PinningRouterMiddleware(get_response)

    def test_pin_on_cookie(self):
        """Thread should pin when the cookie is set."""
        self.request.COOKIES[pinning_cookie()] = 'y'
        self.middleware.process_request(self.request)
        assert this_thread_is_pinned()

    def test_unpin_on_no_cookie(self):
        """Thread should unpin when cookie is absent and method is GET."""
        pin_this_thread()
        self.request.method = 'GET'
        self.middleware.process_request(self.request)
        assert not this_thread_is_pinned()

    def test_pin_on_post(self):
        """Thread should pin when method is POST."""
        self.request.method = 'POST'
        self.middleware.process_request(self.request)
        assert this_thread_is_pinned()

    def test_process_response(self):
        """Make sure the cookie gets set on POSTs but not GETs."""

        self.request.method = 'GET'
        response = self.middleware.process_response(self.request, HttpResponse())
        assert pinning_cookie() not in response.cookies

        self.request.method = 'POST'
        response = self.middleware.process_response(self.request, HttpResponse())
        assert pinning_cookie() in response.cookies
        self.assertEqual(
            response.cookies[pinning_cookie()]['max-age'], pinning_seconds()
        )
        self.assertEqual(
            response.cookies[pinning_cookie()]['samesite'], pinning_cookie_samesite()
        )
        self.assertEqual(
            response.cookies[pinning_cookie()]['httponly'],
            pinning_cookie_httponly() or '',
        )
        self.assertEqual(
            response.cookies[pinning_cookie()]['secure'], pinning_cookie_secure() or ''
        )

    def test_attribute(self):
        """The cookie should get set if the _db_write attribute is True."""
        res = HttpResponse()
        res._db_write = True
        response = self.middleware.process_response(self.request, res)
        assert pinning_cookie() in response.cookies

    def test_db_write_decorator(self):
        """The @db_write decorator should make any view set the cookie."""
        req = self.request
        req.method = 'GET'

        def view(req):
            return HttpResponse()

        response = self.middleware.process_response(req, view(req))
        assert pinning_cookie() not in response.cookies

        @db_write
        def write_view(req):
            return HttpResponse()

        response = self.middleware.process_response(req, write_view(req))
        assert pinning_cookie() in response.cookies


class UsePrimaryDBTests(TestCase):
    def test_decorator(self):
        @use_primary_db
        def check():
            assert this_thread_is_pinned()

        unpin_this_thread()
        assert not this_thread_is_pinned()
        check()
        assert not this_thread_is_pinned()

    def test_decorator_resets(self):
        @use_primary_db
        def check():
            assert this_thread_is_pinned()

        pin_this_thread()
        assert this_thread_is_pinned()
        check()
        assert this_thread_is_pinned()

    def test_context_manager(self):
        unpin_this_thread()
        assert not this_thread_is_pinned()
        with use_primary_db:
            assert this_thread_is_pinned()
        assert not this_thread_is_pinned()

    def test_context_manager_resets(self):
        pin_this_thread()
        assert this_thread_is_pinned()
        with use_primary_db:
            assert this_thread_is_pinned()
        assert this_thread_is_pinned()

    def test_context_manager_exception(self):
        unpin_this_thread()
        assert not this_thread_is_pinned()
        with self.assertRaises(ValueError):
            with use_primary_db:
                assert this_thread_is_pinned()
                raise ValueError
        assert not this_thread_is_pinned()

    def test_multithreaded_unpinning(self):
        thread1_lock = Lock()
        thread2_lock = Lock()
        thread1_lock.acquire()
        thread2_lock.acquire()
        orchestrator = Lock()
        orchestrator.acquire()

        pinned = {}

        def thread1_worker():
            with use_primary_db:
                orchestrator.release()
                thread1_lock.acquire()

            pinned[1] = this_thread_is_pinned()

        def thread2_worker():
            pin_this_thread()
            with use_primary_db:
                orchestrator.release()
                thread2_lock.acquire()

            pinned[2] = this_thread_is_pinned()
            orchestrator.release()

        thread1 = Thread(target=thread1_worker)
        thread2 = Thread(target=thread2_worker)

        # thread1 starts, entering `use_primary_db` from an unpinned state
        thread1.start()
        orchestrator.acquire()

        # thread2 starts, entering `use_primary_db` from a pinned state
        thread2.start()
        orchestrator.acquire()

        # thread2 finishes, returning to a pinned state
        thread2_lock.release()
        thread2.join()
        self.assertEqual(pinned[2], True)

        # thread1 finishes, returning to an unpinned state
        thread1_lock.release()
        thread1.join()
        self.assertEqual(pinned[1], False)


class DeprecationTestCase(TestCase):
    def test_masterslaverouter(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            router = multidb.MasterSlaveRouter()
        assert isinstance(router, ReplicaRouter)
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)

    def test_pinningmasterslaverouter(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            router = multidb.PinningMasterSlaveRouter()
        assert isinstance(router, PinningReplicaRouter)
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)

    @mock.patch.object(multidb, 'get_replica')
    def test_get_slave(self, mock_get_replica):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            multidb.get_slave()
        assert mock_get_replica.called
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)

    def test_use_master(self):
        assert isinstance(multidb.pinning.use_master, use_primary_db.__class__)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            with multidb.pinning.use_master:
                pass
        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)


class SignedCookieSecurityTests(UnpinningTestCase):
    """Tests for signed cookie security improvements."""

    def setUp(self):
        super().setUp()
        # Mock get_response for middleware initialization
        get_response = mock.MagicMock()
        self.middleware = PinningRouterMiddleware(get_response)

    def test_signed_cookie_prevents_tampering(self):
        """Test that forged unsigned cookies are ignored for security."""
        request = HttpRequest()
        request.method = 'GET'
        # Simulate a malicious user setting an unsigned cookie
        request.COOKIES[pinning_cookie()] = 'malicious_value'

        # Mock get_signed_cookie to return None (no valid signed cookie)
        with mock.patch.object(request, 'get_signed_cookie', return_value=None):
            self.middleware.process_request(request)

            # Should NOT pin without valid signed cookie (security improvement)
            self.assertFalse(this_thread_is_pinned())

    def test_valid_signed_cookie_works(self):
        """Test that valid signed cookies properly pin the thread."""
        request = HttpRequest()
        request.method = 'GET'

        # Mock a valid signed cookie
        with mock.patch.object(request, 'get_signed_cookie', return_value='pinned'):
            self.middleware.process_request(request)
            self.assertTrue(this_thread_is_pinned())

    def test_bad_signature_ignored(self):
        """Test that cookies with bad signatures are ignored for security."""
        request = HttpRequest()
        request.method = 'GET'

        # Mock bad signature exception
        with mock.patch.object(request, 'get_signed_cookie', side_effect=BadSignature):
            self.middleware.process_request(request)
            self.assertFalse(this_thread_is_pinned())

    def test_signed_cookie_set_on_write(self):
        """Test that signed cookies are set for write operations."""
        request = HttpRequest()
        request.method = 'POST'
        response = HttpResponse()

        with mock.patch.object(response, 'set_signed_cookie') as mock_set_signed:
            self.middleware.process_response(request, response)

            # Verify signed cookie was set with correct parameters
            from multidb.middleware import pinning_cookie_salt

            mock_set_signed.assert_called_once_with(
                pinning_cookie(),
                value='pinned',
                salt=pinning_cookie_salt(),
                max_age=pinning_seconds(),
                secure=pinning_cookie_secure(),
                httponly=pinning_cookie_httponly(),
                samesite=pinning_cookie_samesite(),
            )

    def test_no_pinning_without_valid_cookie(self):
        """Test that thread is not pinned without valid signed cookie."""
        request = HttpRequest()
        request.method = 'GET'
        request.COOKIES[pinning_cookie()] = 'invalid_unsigned_cookie'

        # Mock get_signed_cookie returning None (no signed cookie)
        with mock.patch.object(request, 'get_signed_cookie', return_value=None):
            self.middleware.process_request(request)

            # Should NOT pin without valid signed cookie
            self.assertFalse(this_thread_is_pinned())


class ReplicaCacheTests(TestCase):
    """Tests for replica list caching optimization."""

    def setUp(self):
        # Clear cache before each test
        import multidb

        multidb._invalidate_replica_cache()

    def tearDown(self):
        # Clear cache after each test to avoid state pollution
        import multidb

        multidb._invalidate_replica_cache()

    @override_settings(REPLICA_DATABASES=['replica1', 'replica2'])
    def test_replica_list_cached(self):
        """Test that replica list is cached after first call."""
        import multidb

        # First call should populate cache
        first_list = multidb._get_replica_databases()

        # Second call should use cache
        second_list = multidb._get_replica_databases()

        # Same objects should be returned (cached)
        self.assertIs(first_list, second_list)

    @override_settings(REPLICA_DATABASES=['replica1'])
    def test_cache_invalidation_on_settings_change(self):
        """Test that cache can be manually invalidated."""
        import multidb

        # First call with replica1
        first_list = multidb._get_replica_databases()

        # Manually invalidate cache (simulates settings change)
        multidb._invalidate_replica_cache()

        # After invalidation, next call rebuilds cache
        with override_settings(REPLICA_DATABASES=['replica2']):
            second_list = multidb._get_replica_databases()

            # Different objects should be returned (cache invalidated)
            self.assertIsNot(first_list, second_list)

    @override_settings(REPLICA_DATABASES=['replica1', 'replica2', 'replica3'])
    def test_thread_safety_of_replica_selection(self):
        """Test that replica selection is thread-safe with realistic concurrency."""
        import multidb

        results = []
        errors = []
        from threading import Barrier

        barrier = Barrier(50)  # 50 threads

        def select_replicas():
            try:
                barrier.wait()  # Synchronize start
                # Each thread selects multiple replicas
                thread_results = []
                for _ in range(100):  # 100 selections per thread
                    thread_results.append(multidb.get_replica())
                results.append(thread_results)
            except Exception as e:
                errors.append(e)

        # Start 50 threads (more realistic)
        threads = [Thread(target=select_replicas) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should occur
        self.assertEqual(len(errors), 0, f'Errors occurred: {errors}')
        # All threads should return results
        self.assertEqual(len(results), 50)
        # All results should contain valid replica names
        for thread_results in results:
            for replica in thread_results:
                self.assertIn(replica, ['replica1', 'replica2', 'replica3'])


class EdgeCaseTests(TestCase):
    """Tests for edge cases and error conditions."""

    def setUp(self):
        # Clear cache before each test
        import multidb

        multidb._invalidate_replica_cache()

    def tearDown(self):
        # Clear cache after each test
        import multidb

        multidb._invalidate_replica_cache()

    @override_settings(REPLICA_DATABASES=[])
    def test_empty_replica_databases_list(self):
        """Test behavior when REPLICA_DATABASES is an empty list."""
        import multidb

        # Should fall back to default database
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            replica = multidb.get_replica()

            # Should return default database
            self.assertEqual(replica, DEFAULT_DB_ALIAS)
            # Should issue a warning
            self.assertTrue(len(w) > 0)
            self.assertTrue(issubclass(w[-1].category, UserWarning))
            self.assertIn('No replica databases are configured', str(w[-1].message))

    def test_no_replica_databases_setting(self):
        """Test behavior when REPLICA_DATABASES setting doesn't exist."""
        import multidb

        # Temporarily remove the setting
        original_replica_dbs = getattr(settings, 'REPLICA_DATABASES', None)
        if hasattr(settings, 'REPLICA_DATABASES'):
            delattr(settings, 'REPLICA_DATABASES')

        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter('always')
                # Force cache rebuild
                multidb._invalidate_replica_cache()
                replica = multidb.get_replica()

                # Should return default database
                self.assertEqual(replica, DEFAULT_DB_ALIAS)
                # Should issue a warning
                self.assertTrue(len(w) > 0)
                self.assertTrue(issubclass(w[-1].category, UserWarning))
                self.assertIn('No replica databases are configured', str(w[-1].message))
        finally:
            # Restore original setting
            if original_replica_dbs is not None:
                settings.REPLICA_DATABASES = original_replica_dbs

    @override_settings(REPLICA_DATABASES=['nonexistent_db', 'another_fake_db'])
    def test_invalid_database_aliases(self):
        """Test behavior with invalid database aliases in REPLICA_DATABASES."""
        import multidb

        # This should still work - Django handles missing databases gracefully
        # in most contexts, but we want to ensure our code doesn't crash
        replicas = []
        for _ in range(5):
            replica = multidb.get_replica()
            replicas.append(replica)

        # Should cycle through the configured replicas even if they don't exist
        expected_replicas = ['nonexistent_db', 'another_fake_db']
        for replica in replicas:
            self.assertIn(replica, expected_replicas)

        # Should have proper round-robin behavior
        unique_replicas = set(replicas)
        self.assertEqual(len(unique_replicas), 2)  # Both replicas should be used

    @override_settings(REPLICA_DATABASES=['replica', None, 'replica1'])
    def test_none_in_replica_databases(self):
        """Test behavior when REPLICA_DATABASES contains None values."""
        import multidb

        # Should handle None values gracefully
        replicas = []
        for _ in range(6):  # Multiple cycles
            replica = multidb.get_replica()
            replicas.append(replica)

        # Should cycle through all values, including None
        expected_replicas = ['replica', None, 'replica1']
        for replica in replicas:
            self.assertIn(replica, expected_replicas)

        # None should appear in the results
        self.assertIn(None, replicas)


class CookieSaltSecurityTests(UnpinningTestCase):
    """Tests for cookie salt configuration security."""

    def setUp(self):
        super().setUp()
        get_response = mock.MagicMock()
        self.middleware = PinningRouterMiddleware(get_response)

    @override_settings(MULTIDB_PINNING_COOKIE_SALT='custom_deployment_salt')
    def test_custom_cookie_salt(self):
        """Test that custom cookie salt is used."""
        from multidb.middleware import pinning_cookie_salt

        # Should use custom salt
        self.assertEqual(pinning_cookie_salt(), 'custom_deployment_salt')

        # Should use custom salt when setting cookies
        request = HttpRequest()
        request.method = 'POST'
        response = HttpResponse()

        with mock.patch.object(response, 'set_signed_cookie') as mock_set_signed:
            self.middleware.process_response(request, response)

            # Verify custom salt was used
            mock_set_signed.assert_called_once()
            call_args = mock_set_signed.call_args
            self.assertEqual(call_args[1]['salt'], 'custom_deployment_salt')

    def test_default_cookie_salt(self):
        """Test that default cookie salt is used when not configured."""
        from multidb.middleware import pinning_cookie_salt

        # Should use default salt
        self.assertEqual(pinning_cookie_salt(), 'multidb_pinning')

    @override_settings(MULTIDB_PINNING_COOKIE_SALT='')
    def test_empty_cookie_salt(self):
        """Test behavior with empty cookie salt."""
        from multidb.middleware import pinning_cookie_salt

        # Should use empty string as salt (valid but insecure)
        self.assertEqual(pinning_cookie_salt(), '')

        # Should still work with empty salt
        request = HttpRequest()
        request.method = 'POST'
        response = HttpResponse()

        with mock.patch.object(response, 'set_signed_cookie') as mock_set_signed:
            self.middleware.process_response(request, response)

            # Should still set cookie with empty salt
            mock_set_signed.assert_called_once()
            call_args = mock_set_signed.call_args
            self.assertEqual(call_args[1]['salt'], '')

    @override_settings(MULTIDB_PINNING_COOKIE_SALT='deployment_1_salt')
    def test_salt_prevents_cross_deployment_attacks(self):
        """Test that different salts prevent cross-deployment cookie attacks."""
        request = HttpRequest()
        request.method = 'GET'

        # Simulate cookie signed with different deployment's salt
        with mock.patch.object(request, 'get_signed_cookie', side_effect=BadSignature):
            self.middleware.process_request(request)

            # Should not pin due to signature mismatch
            self.assertFalse(this_thread_is_pinned())


class SecretKeySecurityTests(UnpinningTestCase):
    """Tests for SECRET_KEY security edge cases."""

    def setUp(self):
        super().setUp()
        get_response = mock.MagicMock()
        self.middleware = PinningRouterMiddleware(get_response)

    def test_missing_secret_key(self):
        """Test behavior when SECRET_KEY is missing or None."""
        request = HttpRequest()
        request.method = 'POST'
        response = HttpResponse()

        # Temporarily remove SECRET_KEY
        original_secret_key = getattr(settings, 'SECRET_KEY', None)
        if hasattr(settings, 'SECRET_KEY'):
            delattr(settings, 'SECRET_KEY')

        try:
            # Should handle missing SECRET_KEY gracefully
            with self.assertRaises((AttributeError, ImproperlyConfigured)):
                self.middleware.process_response(request, response)
        finally:
            # Restore original SECRET_KEY
            if original_secret_key is not None:
                settings.SECRET_KEY = original_secret_key

    @override_settings(SECRET_KEY='')
    def test_empty_secret_key(self):
        """Test behavior with empty SECRET_KEY."""
        request = HttpRequest()
        request.method = 'POST'
        response = HttpResponse()

        # Should handle empty SECRET_KEY (Django will likely fail)
        with self.assertRaises((ValueError, ImproperlyConfigured)):
            self.middleware.process_response(request, response)

    @override_settings(SECRET_KEY='weak')
    def test_weak_secret_key(self):
        """Test behavior with weak SECRET_KEY."""
        request = HttpRequest()
        request.method = 'POST'
        response = HttpResponse()

        # Should still work with weak key (Django's responsibility to validate)
        self.middleware.process_response(request, response)

        # Cookie should be set despite weak key
        self.assertIn(pinning_cookie(), response.cookies)

    def test_secret_key_change_invalidates_cookies(self):
        """Test that changing SECRET_KEY invalidates existing cookies."""
        request = HttpRequest()
        request.method = 'GET'

        # Set a cookie value that would be valid with current SECRET_KEY
        request.COOKIES[pinning_cookie()] = 'some_cookie_value'

        # Mock get_signed_cookie to simulate SECRET_KEY change
        # (cookies signed with old key will have BadSignature with new key)
        with mock.patch.object(request, 'get_signed_cookie', side_effect=BadSignature):
            self.middleware.process_request(request)

            # Should not pin due to signature validation failure
            self.assertFalse(this_thread_is_pinned())

    def test_malformed_cookie_data(self):
        """Test behavior with malformed cookie data that could cause signing errors."""
        request = HttpRequest()
        request.method = 'GET'

        # Mock get_signed_cookie to simulate various signing errors
        error_cases = [
            BadSignature('Invalid signature'),
            ValueError('Invalid base64 data'),
            TypeError('Cookie data not string'),
        ]

        for error in error_cases:
            with self.subTest(error=error.__class__.__name__):
                unpin_this_thread()  # Reset state

                with mock.patch.object(request, 'get_signed_cookie', side_effect=error):
                    # Should handle all errors gracefully
                    self.middleware.process_request(request)

                    # Should not pin on any error
                    self.assertFalse(this_thread_is_pinned())
