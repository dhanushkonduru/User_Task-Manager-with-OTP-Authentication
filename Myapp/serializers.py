# Myapp/serializers.py

from rest_framework import serializers
from .models import Task, User
from rest_framework import serializers


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'due_date', 'status', 'user']
        extra_kwargs = {'user': {'required': False}}


class UserTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'due_date', 'status']


class UserSerializer(serializers.ModelSerializer):
    tasks = UserTaskSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'email', 'phone_number', 'country_code', 'tasks']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            phone_number=validated_data['phone_number'],
            country_code=validated_data['country_code']
        )
        return user


class RegisterSerializer(serializers.Serializer):
    phone = serializers.CharField(source='phone_number')
    country_code = serializers.CharField(max_length=5)

    class Meta:
        model = User
        fields = ['username', 'password', 'country_code', 'phone']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            phone_number=validated_data['phone_number'],
            country_code=validated_data['country_code']
        )
        return user


class LoginSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)
    country_code = serializers.CharField(max_length=5)
    otp = serializers.CharField(max_length=6)
