from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
import uuid
from rest_framework_simplejwt.tokens import RefreshToken
# Create your models here.

class User(AbstractUser):
    USER_TYPE_CHOICES = [
        ('individual', 'Individual'),
        ('corporate', 'Corporate'),
    ]
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)

    def __str__(self):
        return self.username



class Device(models.Model):
    STATUS_CHOICES = [
        ('offline', 'Offline'),
        ('Online', 'Online'),
        ('stand_by','Stand_by')
    ]
    device_name = models.CharField(max_length=100)
    image=models.ImageField( upload_to="Device-Images", null=True,blank=True)
    device_type = models.CharField( max_length=100)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="devices"
    )

    location = models.CharField(max_length=50)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    data = models.FloatField(validators=[MinValueValidator(0)], null=True,blank=True)
    data_type = models.CharField(max_length=50, null=True,blank=True)
    device_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return self.device_name+"("+self.user.username +")"


class Room(models.Model):
    room_name = models.CharField(max_length=100)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="rooms")
    devices = models.ManyToManyField(Device, related_name="rooms", blank=True)

    def __str__(self):
        return self.room_name



class Alert(models.Model):
    
    device = models.ForeignKey(
        Device,  on_delete=models.CASCADE, related_name="alerts")
    alert_type =models.CharField( max_length=50)
    message = models.CharField(max_length=200)
    time = models.TimeField(auto_now_add=True)
    def __str__(self):
        return self.alert_type+": "+self.message
#Create a token for the user after the registration and send a welcome message via email
@receiver(post_save,sender=User)

def generate_post_token(sender, instance=None, created=False, **kwargs):
    if created:
        # Create a token for the newly created user
        RefreshToken.for_user(instance)
        
        # Send an email to the newly created user
        subject = 'Welcome to Our Platform'
        message = f'Hello {instance.username},\n\nThank you for registering on our platform. Your account has been created successfully.'
        from_email = settings.DEFAULT_FROM_EMAIL  # or your desired email address
        recipient_list = [instance.email]

        send_mail(subject, message, from_email, recipient_list)
#Emailing the alert to the user
@receiver(post_save,sender=Alert)

def send_alert(sender, instance=None, created=False, **kwargs):
    if created:
        # Send an email to notify user about the alert
        device=instance.device
        user=device.user
        subject = 'New Alert From:'+ device.device_name
        message = f'Alert: {instance.alert_type},{instance.time},\n\n{instance.message}'
        from_email = settings.DEFAULT_FROM_EMAIL  
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)