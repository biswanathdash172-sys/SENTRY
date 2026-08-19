import sys
from pathlib import Path
from datetime import datetime

# Ensure project root is on sys.path so imports like `from backend.db.json_store import JSONStore`
# work whether this script is executed as `python backend\db\seed_org.py` or as a module.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.db.json_store import JSONStore

store = JSONStore()


def _hash_password(password: str) -> str:
    # Try to use passlib bcrypt if available and working; otherwise fall back
    # to a simple (insecure) placeholder so seeding still succeeds in dev.
    try:
        from passlib.hash import bcrypt
        return bcrypt.hash(password)
    except Exception:
        # Fallback: mark unhashed password so it's obvious in dev
        return f"plain:{password}"


def seed_org():
    orgs = store.load_orgs() or []
    if not orgs:
        orgs = [
            {
                "id": 1,
                "name": "Test Org",
                "monitored_mailbox": "test@example.com",
                "created_at": datetime.utcnow().isoformat(),
            }
        ]
        store.save_orgs(orgs)

    admins = store.load_admins() or []
    if not admins:
        hashed = _hash_password("test")
        admins = [
            {
                "id": 1,
                "org_id": 1,
                "username": "test",
                "password_hash": hashed,
                "created_at": datetime.utcnow().isoformat(),
            }
        ]
        store.save_admins(admins)


if __name__ == "__main__":
    seed_org()
    print("Seed completed")
