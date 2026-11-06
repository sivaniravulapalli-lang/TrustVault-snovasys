from types import SimpleNamespace

from app.authz import can     
from app.models import Role


def test_unknown_action_is_denied_even_for_owner():
    owner = SimpleNamespace(id=1, role=Role.owner)
    doc = SimpleNamespace(id=10, owner_id=1, deleted_at=None)
    for action in ["banana", "", "READ", "admin"]:
        assert can(owner, doc, action, db=None) is False