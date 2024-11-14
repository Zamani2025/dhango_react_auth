from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, smart_str, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import *

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, max_length=68, min_length=6)
    password2 = serializers.CharField(write_only=True, max_length=68, min_length=6)
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')
        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        return user
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(write_only=True, max_length=68, min_length=6)
    full_name = serializers.CharField(read_only=True, max_length=255)
    access_token = serializers.CharField(read_only=True, max_length=255)
    refresh_token = serializers.CharField(read_only=True, max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']
    
    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        request = self.context.get('request')
        user = authenticate(request, username=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        
        if not user.is_verified:
            raise AuthenticationFailed('Email has not been verified')
        
        user_token = user.tokens()

        return {
            'email': user.email,
            'full_name': user.get_full_name(),
            'access_token': str(user_token.get('access')),
            'refresh_token': str(user_token.get('refresh')),
        }
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=6)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            request = self.context.get('request')
            domain = get_current_site(request).domain
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = f"http://{domain}{relative_link}"
            email_body = f"Hello, \n Use link below to reset your password \n {absurl}"
            data = {
                'email_body': email_body,
                'to_email': user.email,
                'email_subject': 'Reset your password'
            }
            send_normal_email(data)
            
        else:
            raise AuthenticationFailed('No user found with this email address')
        return super().validate(attrs)
    
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, max_length=68, min_length=6)
    confirm_password = serializers.CharField(write_only=True, max_length=68, min_length=6)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)
    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']
    
    def validate(self, attrs):
        try:
            password = attrs.get('password', '')
            confirm_password = attrs.get('confirm_password', '')
            token= attrs.get('token', '')
            uidb64 = attrs.get('uidb64', '')
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid or has expired', 401)
            
            if password != confirm_password:
                raise serializers.ValidationError("Passwords do not match", 40)
            
            user.set_password(password)
            user.save()

            return user
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid or has expired', 401)
        
