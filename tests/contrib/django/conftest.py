from django.conf import settings


def pytest_configure():
    if not settings.configured:
        settings.configure(
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            INSTALLED_APPS=[
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "django.contrib.sessions",
                "cqrs_ddd_auth",
            ],
            MIDDLEWARE=[
                "django.contrib.sessions.middleware.SessionMiddleware",
                "django.contrib.auth.middleware.AuthenticationMiddleware",
            ],
            SECRET_KEY="test_secret",
            ROOT_URLCONF="tests.contrib.django.urls",
            CQRS_DDD_AUTH_ALLOW_ANONYMOUS=True,
        )
        import django

        django.setup()
