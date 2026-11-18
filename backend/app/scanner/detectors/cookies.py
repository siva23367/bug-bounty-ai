from http.cookies import CookieError, SimpleCookie

from .base import finding


def detect(r):
    issues = []
    for raw in r.headers.get_list('set-cookie'):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            issues.append({'cookie': '[unparseable]', 'missing': ['manual review required']})
            continue
        for name, item in cookie.items():
            missing = [flag for flag in ('secure', 'httponly', 'samesite') if not item[flag]]
            if missing:
                issues.append({'cookie': name, 'missing': missing})
    if not issues:
        return []
    return [finding(r, 'cookies', 'Cookie protection attributes require review', 'Low',
                    'One or more response cookies lack browser security attributes.',
                    'Impact depends on whether the cookie protects a session; not every cookie needs HttpOnly.',
                    'Set Secure, HttpOnly and an appropriate SameSite policy for session cookies.', {'cookies': issues})]
