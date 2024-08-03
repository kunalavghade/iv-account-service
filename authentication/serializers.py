from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib import auth
from django.contrib.auth.tokens import  PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .models import User


class RegisterSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, min_length=6, write_only=True)
    email = serializers.EmailField(max_length = 255, min_length=6)
    username = serializers.CharField(max_length=255, min_length=3)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        username:str = attrs.get('username','')

        if not username.isalnum():
            raise serializers.ValidationError('Username should have aphanumeric character')

        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class EmailVarificationSerializer(serializers.Serializer):
    token =serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=68, min_length=6, read_only= True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')

        user = auth.authenticate(email = email, password= password)

        if not user:
            raise AuthenticationFailed('Invalid Credential, try again')
        
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        
        return {
            'email': user.email,
            'username': user.get_username,
            'tokens': user.tokens()
        }

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=6)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        return super().validate(attrs['data'])
    

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length = 6, max_length=68, write_only=True)
    token = serializers.CharField(min_length = 1, write_only=True)
    uidb64 = serializers.CharField(min_length = 1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']


    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id = id)

            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                raise AuthenticationFailed('The reset link is expired', 401)
            
            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
             raise AuthenticationFailed('The reset link is expired', 401)
        return super().validate(attrs)

