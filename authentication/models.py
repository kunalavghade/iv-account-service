from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import APIException
from rest_framework import status

class UserManager(BaseUserManager):

    def create_user(self, username: str, email: str, password : str | None= None):
        if username is None:
            raise APIException('User should have username')
        if email is None:
            raise APIException('User should have email')
        
        if User.objects.filter(username = username).first():
            raise APIException('Username is already taken')

        if User.objects.filter(email = email).first():
            raise APIException('Email is already taken')
        
        user = self.model(username = username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_supperuser(self, username, email, password = None):
        if password is None:
            raise TypeError('Password should not be none')
        if email is None:
            raise TypeError('User should have email')
        
        user = self.create_user(username=username, email=email, password=password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length = 255, unique=True, db_index=True)
    email = models.EmailField(max_length = 255, unique=True, db_index=True)
    is_verified = models.BooleanField(default = False)
    is_active = models.BooleanField(default = True)
    is_staff = models.BooleanField(default = False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
    
        

