from rest_framework import serializers
from .models import Message
from myapp.hashers import *


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = '__all__'


class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value: str) -> str:
        """Hash the password."""
        hasher = SHA256PasswordHasher()
        return hasher.encode(value, salt=None)

    def validate_username(self, value: str) -> str:
        """Check if the username already exists."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)