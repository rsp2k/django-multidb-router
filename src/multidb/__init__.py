"""
With :class:`multidb.ReplicaRouter` all read queries will go to a replica
database;  all inserts, updates, and deletes will do to the ``default``
database.

First, define ``REPLICA_DATABASES`` in your settings.  It should be a list of
database aliases that can be found in ``DATABASES``::

    DATABASES = {
        'default': {...},
        'shadow-1': {...},
        'shadow-2': {...},
    }
    REPLICA_DATABASES = ['shadow-1', 'shadow-2']

Then put ``multidb.ReplicaRouter`` into DATABASE_ROUTERS::

    DATABASE_ROUTERS = ('multidb.ReplicaRouter',)

The replica databases will be chosen in round-robin fashion.

If you want to get a connection to a replica in your app, use
:func:`multidb.get_replica`::

    from django.db import connections
    import multidb

    connection = connections[multidb.get_replica()]
"""

import hashlib
import random
import threading
import warnings

from django.conf import settings

from .pinning import db_write, this_thread_is_pinned  # noqa

VERSION = (0, 11, 0)
__version__ = '.'.join(map(str, VERSION))

DEFAULT_DB_ALIAS = 'default'


# Thread-safe replica cache
_replica_cache = {'databases': None, 'lock': threading.Lock(), 'index': 0}


def _get_replica_settings_hash():
    """Generate hash of current replica database settings for cache invalidation."""
    replica_dbs = getattr(settings, 'REPLICA_DATABASES', None)
    slave_dbs = getattr(settings, 'SLAVE_DATABASES', None)

    # Create deterministic hash of current settings
    settings_data = {
        'replica_databases': sorted(replica_dbs) if replica_dbs else None,
        'slave_databases': sorted(slave_dbs) if slave_dbs else None,
    }

    return hashlib.md5(str(settings_data).encode()).hexdigest()


def _get_replica_databases():
    """Get cached replica databases list, rebuilding only when needed."""
    with _replica_cache['lock']:
        # Fast path - return cached databases if available
        if _replica_cache['databases'] is not None:
            return _replica_cache['databases']

        # First time or cache invalidated - rebuild
        dbs = None
        if hasattr(settings, 'REPLICA_DATABASES'):
            dbs = list(settings.REPLICA_DATABASES)
        elif hasattr(settings, 'SLAVE_DATABASES'):
            warnings.warn(
                '[multidb] The SLAVE_DATABASES setting has been deprecated. '
                'Please switch to the REPLICA_DATABASES setting.',
                DeprecationWarning,
                stacklevel=2,
            )
            dbs = list(settings.SLAVE_DATABASES)

        if not dbs:
            warnings.warn(
                '[multidb] No replica databases are configured! '
                'You can configure them with the REPLICA_DATABASES setting.',
                UserWarning,
                stacklevel=2,
            )
            _replica_cache['databases'] = [DEFAULT_DB_ALIAS]
            return _replica_cache['databases']

        # Shuffle the list so the first replica isn't slammed during startup.
        random.shuffle(dbs)

        # Cache the new replica list
        _replica_cache['databases'] = dbs
        return _replica_cache['databases']


def _invalidate_replica_cache():
    """Invalidate the replica cache - for testing and settings changes."""
    with _replica_cache['lock']:
        _replica_cache['databases'] = None
        _replica_cache['index'] = 0


def get_replica():
    """Returns the alias of a replica database using thread-safe round-robin."""
    databases = _get_replica_databases()

    # Thread-safe round-robin selection
    with _replica_cache['lock']:
        index = _replica_cache['index']
        _replica_cache['index'] = (index + 1) % len(databases)
        return databases[index]


def get_slave():
    warnings.warn(
        '[multidb] The get_slave() method has been deprecated. '
        'Please switch to the get_replica() method.',
        DeprecationWarning,
        stacklevel=2,
    )
    return get_replica()


class DeprecationMixin:
    def __init__(self, *args, **kwargs):
        warnings.warn(
            '[multidb] The MasterSlaveRouter and PinningMasterSlaveRouter '
            'classes have been deprecated. Please switch to the ReplicaRouter '
            'and PinningReplicaRouter classes respectively.',
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class ReplicaRouter:
    """Router that sends all reads to a replica, all writes to default."""

    def db_for_read(self, model, **hints):
        """Send reads to replicas in round-robin."""
        return get_replica()

    def db_for_write(self, model, **hints):
        """Send all writes to the master."""
        return DEFAULT_DB_ALIAS

    def allow_relation(self, obj1, obj2, **hints):
        """Allow all relations, so FK validation stays quiet."""
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        return db == DEFAULT_DB_ALIAS

    def allow_syncdb(self, db, model):
        """Only allow syncdb on the master."""
        return db == DEFAULT_DB_ALIAS


class PinningReplicaRouter(ReplicaRouter):
    """Router that sends reads to master if a certain flag is set. Writes
    always go to master.

    Typically, we set a cookie in middleware for certain request HTTP methods
    and give it a max age that's certain to be longer than the replication lag.
    The flag comes from that cookie.

    """

    def db_for_read(self, model, **hints):
        """Send reads to replicas in round-robin unless this thread is
        "stuck" to the master."""
        return DEFAULT_DB_ALIAS if this_thread_is_pinned() else get_replica()


class MasterSlaveRouter(DeprecationMixin, ReplicaRouter):
    pass


class PinningMasterSlaveRouter(DeprecationMixin, PinningReplicaRouter):
    pass
