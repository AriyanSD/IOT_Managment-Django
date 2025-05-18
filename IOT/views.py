from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.authtoken.models import Token
from .models import Device, Room, Alert
from .serializers import DeviceSerializer, RoomSerializer, AlertSerializer, UserRegisterationSerializer
from rest_framework.permissions import IsAuthenticated
from django_rest_passwordreset.signals import reset_password_token_created
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from . import forms
from django.shortcuts import render
from django.urls import reverse
import requests
from django.utils.http import urlencode
from django.contrib.sites.shortcuts import get_current_site
# from rest_framework_simplejwt.tokens import RefreshToken

# The viewset for device model which handle the CRUD operations built in
class DeviceViewSet(viewsets.ModelViewSet):
    serializer_class = DeviceSerializer
    # Make the viewset authenticate required
    permission_classes = [IsAuthenticated]
    # Over writing the query set: in this case to accses to the Authed user
    # and filter the qury set based on it

    def get_queryset(self):
        # Return only the devices that belong to the logged-in user
        query_set = Device.objects.filter(user=self.request.user)

        if self.request.method == 'GET':
            # Applying the search and filtering query params
            # on our query set if there is one or more
            search_name = self.request.query_params.get('search_name', None)

            filter_status = self.request.query_params.get(
                'filter_status', None)

            filter_type = self.request.query_params.get('filter_type', None)

            if search_name:
                query_set = query_set.filter(
                    device_name__icontains=search_name)
            if filter_status:
                query_set = query_set.filter(status=filter_status)

            if filter_type:
                query_set = query_set.filter(device_type=filter_type)

        return query_set

    # cahnge the logic of saving for Create and Put to do an additional step before saving the
    def perform_create(self, serializer):
        # Set the user to the authenticated user
        serializer.save(user=self.request.user)

    # Over writting the srializer to add aditional arguments
    def get_serializer(self, *args, **kwargs):
        # Add extra arguments to the context here
        kwargs['context'] = {
            'current_user': self.request.user
        }
        return super().get_serializer(*args, **kwargs)

    # adding custom end point to the view set
    @action(detail=True, methods=['get'])
    # get all alerts of selected device
    def get_alerts(self, request, pk=None):
        device = self.get_object()
        alerts = device.alerts.all()  # Get all alerts related to this device

        serializer = AlertSerializer(alerts, many=True)
        return Response(serializer.data)

# The viewset for Room model which handle the CRUD operations built in


class RoomViewSet(viewsets.ModelViewSet):
    serializer_class = RoomSerializer
    # Make the viewset authenticate required
    permission_classes = [IsAuthenticated]
    # Over writing the query set

    def get_queryset(self):
        # Return only the devices that belong to the logged-in user
        return Room.objects.filter(user=self.request.user)

# The viewset for Alert model which handle the CRUD operations built in


class AlertViewSet(viewsets.ModelViewSet):
    serializer_class = AlertSerializer
    # Make the viewset authenticate required
    permission_classes = [IsAuthenticated]

    # Over writting the queryset
    def get_queryset(self):
        # Get all devices that belong to the logged-in user
        user_devices = Device.objects.filter(user=self.request.user)

        # Filter alerts based on those devices
        query_set = Alert.objects.filter(device__in=user_devices)
        if self.request.method == 'GET':
            search_message = self.request.query_params.get(
                'search_message', None)

            search_device = self.request.query_params.get(
                'search_device', None)

            filter_type = self.request.query_params.get('filter_type', None)
            order = self.request.query_params.get('order', None)

            if search_message:
                query_set = query_set.filter(
                    message__icontains=search_message)
            if search_device:
                query_set = query_set.filter(
                    device__device_name__icontains=search_device)

            if filter_type:
                query_set = query_set.filter(alert_type__icontains=filter_type)

            if order == "-time":
                query_set = query_set.order_by('-time')

            elif order == "time":
                query_set = query_set.order_by('time')
        return query_set

    @action(detail=False, methods=['get'])
    # Get the most recent alert
    def most_recent(self, request):
        recent_alert = Alert.objects.order_by('time').first()
        serializer = self.get_serializer(recent_alert)
        return Response(serializer.data)

# user registratiion view


@api_view(["POST"])
def user_registration(request):
    if request.method == "POST":
        serializer = UserRegisterationSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            user = serializer.save()
            data["response"] = "succsufully registred a new User"
            # log in after registration
            auth_token = Token.objects.get(user=user).key
            data["token"] = auth_token
        else:
            # get errors of the serializer
            data = serializer.errors

        return Response(data)
    return Response({"error": "Not Allowed Http method."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def change_user(request):
    if request.method == 'PUT':
        user = request.user
        serializer = UserRegisterationSerializer(
            instance=user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"response": "User information updated successfully!"})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response({"error": "Not Allowed Http method."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


# @api_view(['POST'])
# def logout(request):
#     try:
#         # Get the refresh token from the request body
#         refresh_token = request.data.get('refresh_token')

#         if not refresh_token:
#             return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

#         # Blacklist the refresh token
#         token = RefreshToken(refresh_token)
#         token.blacklist()

#         return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
#     except Exception as e:
#         return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['POST'])

# def create_alert(request):
#     if request.method =='POST':
#         serializer = AlertSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#     return Response({"error": "Not Allowed Http method."},status=status.HTTP_405_METHOD_NOT_ALLOWED)

# Send an Email contain the Reset Password view URL after the reset password token generated
@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    """
    Handles password reset tokens by sending an email with the reset token and a URL
    """
    # Build the reset password URL with the token as a query parameter
    # Get current domain (useful for development/localhost)
    domain = get_current_site(instance.request).domain

    reset_url = f"http://{domain}{reverse('password_reset_view')}?{
        urlencode({'token': reset_password_token.key})}"

    # Prepare the email content
    email_plaintext_message = f"Click the following link to reset your password: {
        reset_url}"

    # Send the email
    send_mail(
        # Title:
        "Password Reset",
        # Message:
        email_plaintext_message,
        # From:
        settings.DEFAULT_FROM_EMAIL,
        # To:
        [reset_password_token.user.email]
    )

# Reset Password view with the form for entering new one


def reset_password_view(request):
    if request.method == "GET":
        form = forms.ResetPasswordForm
        return render(request, "IOT/reset_password.html", {
            "form": form, "errors": None
        })
    elif request.method == "POST":
        form = forms.ResetPasswordForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password']
            token = request.GET.get('token', None)
            data = {
                'token': token,
                'password': new_password
            }

            # Send POST request to reset_password_confirm endpoint
            confirm_url = request.build_absolute_uri(
                reverse('password_reset_confirm'))
            response = requests.post(confirm_url, data=data)

            # Handle the response from the confirm endpoint
            if response.status_code == 200:
                return render(request, "IOT/reset_succses.html")
            else:
                errors = response.json()

                return render(request, "IOT/reset_password.html", {"form": form, "errors": errors})

        else:
            return render(request, "IOT/reset_password.html", {"form": form, "errors": None})
