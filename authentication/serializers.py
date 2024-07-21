from rest_framework import serializers
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