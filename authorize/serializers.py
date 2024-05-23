from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.db import transaction
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.settings import api_settings

from authorize.models import User


class DRFTokenSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims if necessary
        return token

    def validate(self, attrs):
        username_or_email = attrs.get("username")
        password = attrs.get("password")

        user = authenticate(
            request=self.context.get('request'),
            username=username_or_email,
            password=password,
        )

        if not user:
            user = User.objects.filter(email=username_or_email).first()
            if user and user.check_password(password):
                update_last_login(None, user)
            else:
                error = {"user": ["No active account found with the given credentials"]}
                raise ValidationError(detail=error)

        refresh = self.get_token(user)
        data = {}
        data['access'] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)

        return data


class UserRegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    @transaction.atomic
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
        )
        user.save()
        return user


class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
    )
    repeat_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['password', 'repeat_password']

    def validate(self, attrs):
        if attrs['password'] != attrs['repeat_password']:
            error = {"password": ["Password fields didn't match"]}
            raise serializers.ValidationError(detail=error)

        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance


class SendEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

