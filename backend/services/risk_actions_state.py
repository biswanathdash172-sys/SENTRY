ALLOWED_TRANSITIONS = {
    'pending': {'admin_approved', 'admin_denied', 'completed'},
    'completed': set()
}

ALERT_ACTION_ALLOWED_TRANSITIONS = {
    'manual': {'approved', 'denied'},
    'auto': {'executed', 'blocked'},
    'approved': {'executing', 'executed'},
    'denied': set(),
    'executing': {'executed', 'blocked'},
    'executed': set(),
    'blocked': set()
}
