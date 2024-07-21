from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib import auth
from .models import User


class RegisterSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, min_length=6, write_only=True)
    email = serializers.EmailField(max_length = 255, min_length=6)
    username = serializers.CharField(max_length = 255, min_length=6 )

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):

        email:str = attrs.get('email','')
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
    email = serializers.CharField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=68, min_length=6, read_only= True)
    tokens = serializers.CharField(max_length=255, min_length=6, read_only= True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')
        print(attrs)

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