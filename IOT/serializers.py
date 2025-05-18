from rest_framework import serializers
from django.contrib.auth import get_user_model
from. import models
# Default User model we use for authentication
User = get_user_model()


class UserRegisterationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={"input_type": "password"}, write_only=True, required=True)
    user_type = serializers.ChoiceField(
        choices=User.USER_TYPE_CHOICES, required=True)

    class Meta:
        model = User
        fields = ["username", "email", "password", "password2", "user_type"]
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def create(self, validated_data):
        user = User(
            # Set the validated data
            username=validated_data["username"],
            email=validated_data["email"],
            user_type=validated_data["user_type"]
        )
        password = validated_data["password"]
        password2 = validated_data["password2"]
        if password != password2:
            raise serializers.ValidationError(
                {"password": "passwords not match"})
        # Hash the password and set it if the confirm value was matched
        user.set_password(password)

        user.save()
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get("username", instance.username)
        instance.email = validated_data.get("email", instance.email)

        password = validated_data.get("password", None)
        password2 = validated_data.get("password2", None)

        if password and password == password2:
            instance.set_password(password)
        elif password and password != password2:
            raise serializers.ValidationError(
                {"password": "Passwords do not match."})

        instance.save()
        return instance


class DeviceSerializer(serializers.ModelSerializer):
    rooms = serializers.PrimaryKeyRelatedField(
        queryset=models.Room.objects.all(), many=True)

    class Meta:
        model = models.Device
        # Include 'rooms' in the fields
        fields = ['id', 'device_name', 'rooms', 'image']
        read_only_fields = ['id', "user"]

    def validate_rooms(self, value):
        # Access the context to get the current user
        current_user = self.context['current_user']
        # Fetch the IDs of the rooms that belong to the current user
        user_room_ids = set(current_user.rooms.values_list('id', flat=True))

        # Extract IDs from the rooms in the value
        room_ids = set(room.id for room in value)
        if not all(room_id in user_room_ids for room_id in room_ids):
            raise serializers.ValidationError(
                "You can only add rooms that belong to you.")
        return value

    def create(self, validated_data):
        rooms_data = validated_data.pop('rooms')
        device = models.Device.objects.create(**validated_data)
        device.rooms.set(rooms_data)  # Associate rooms with the device
        return device

    def update(self, instance, validated_data):
        rooms_data = validated_data.pop('rooms')
        instance.device_name = validated_data.get(
            'device_name', instance.device_name)
        instance.save()
        instance.rooms.set(rooms_data)  # Update associated rooms
        return instance


class RoomSerializer(serializers.ModelSerializer):
    devices = serializers.PrimaryKeyRelatedField(
        queryset=models.Device.objects.all(), many=True)

    class Meta:
        model = models.Room
        fields = ['id', 'room_name', 'user', 'devices']
        read_only_fields = ['id', "user"]

    def create(self, validated_data):
        devices = validated_data.pop('devices')
        room = models.Room.objects.create(**validated_data)
        room.devices.set(devices)
        return room

    def update(self, instance, validated_data):
        devices = validated_data.pop('devices')
        instance.room_name = validated_data.get(
            'room_name', instance.room_name)
        instance.user = validated_data.get('user', instance.user)
        instance.save()
        instance.devices.set(devices)
        return instance


class AlertSerializer(serializers.ModelSerializer):
    device_token = serializers.UUIDField(write_only=True)

    class Meta:
        model = models.Alert
        fields = ['alert_type', 'message', 'device_token', 'device']

    def create(self, validated_data):
        device_token = validated_data.pop('device_token')

        try:
            # Find the device using the token
            device = models.Device.objects.get(device_token=device_token)
        except models.Device.DoesNotExist:
            raise serializers.ValidationError("Invalid device token.")

        # Create the alert for the device
        alert = models.Alert.objects.create(device=device, **validated_data)
        return alert
