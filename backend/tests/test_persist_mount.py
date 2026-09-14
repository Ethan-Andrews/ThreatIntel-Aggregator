import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db as db_module


def test_check_persist_mount_is_a_noop():
    """check_persist_mount() is a deliberate no-op post-Postgres-migration --
    there is no local persist-volume sqlite file to mount-check anymore (see
    its docstring in db.py). This replaces the old dir-missing/same-device/
    different-device tests, which exercised mount-detection logic that no
    longer exists and referenced db.PERSIST_DB_PATH, a sqlite-era global
    that was removed."""
    assert db_module.check_persist_mount() is True
