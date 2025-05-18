from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

"""Defult Rest Token Authentication"""
# from rest_framework.authtoken.views import obtain_auth_token
# from django.contrib.auth import views as auth_views

# Define Router and register viewsets
router = DefaultRouter()
router.register(r'device', views.DeviceViewSet, basename="device")
router.register(r'room', views.RoomViewSet, basename="room")
router.register(r'alert', views.AlertViewSet, basename="alert")

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(),
         name='token_obtain_pair'),  # Get access & refresh tokens
    path('api/token/refresh/', TokenRefreshView.as_view(),
         name='token_refresh'),  # Refresh access token
    path('api/token/verify/', TokenVerifyView.as_view(),
         name='token_verify'),  # Verify token validity
    # path("api/token/logout",views.logout,name="log_out_user"),
    # path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    # path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    # path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('password_reset/', reset_password_request_token,
         name='password_reset'),  # Get reset Password token
    path("password_reset_view/", views.reset_password_view,
         name="password_reset_view"),  # Reset Pasword view
    path('password_reset/confirm/', reset_password_confirm,
         name='password_reset_confirm'),  # Confirm the password that reseted
    path('', include(router.urls)), # Include the router URL's
]
