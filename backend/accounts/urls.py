"""URL routes for the accounts app (mounted at /api/auth/)."""

from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("me/", views.me, name="me"),
    path("csrf/", views.csrf, name="csrf"),
    
    path("github/", views.github_login, name="github"),
    path("github/callback/", views.github_callback, name="github-callback"),
]
