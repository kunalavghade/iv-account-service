from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status, views 
from rest_framework_simplejwt.tokens import RefreshToken 
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import jwt

from .serializers import RegisterSerializer, EmailVarificationSerializer, LoginSerializer
from .models import User
from .utils import Util



class RegisterView(GenericAPIView):

    serializer_class = RegisterSerializer 

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data

        user = User.objects.get(email = user_data['email'])
        token = RefreshToken.for_user(user=user).access_token

        current_site = get_current_site(request=request).domain
        relativeLink= reverse('email-verify')
       
        absurl = 'http://' + current_site + relativeLink + "?token=" + str(token) 
        email_body = 'Hi '+ user.username + 'use link below to verify your email \n' + absurl
        data = { 'domain': current_site , 'subject': 'Verify your email', 'email_body': email_body, 'to_email': user.email}
        
        
        Util.send_emil(data)

        return Response({'user': user_data, 'link': absurl}, status= status.HTTP_201_CREATED)
    
class VerifyEmail(views.APIView):
    serializer_class = EmailVarificationSerializer

    token_param_config = openapi.Parameter('token', in_= openapi.IN_QUERY, description='token in query param', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY,options={"verify_signature": False})

            user = User.objects.get(id = payload['user_id'])

            if not user.is_verified:
                user.is_verified = True
            user.save()
            return Response({'email': 'Successfully Activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as e:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as e: 
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)
        

class LoginAPIView(GenericAPIView):
    
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        print( serializer.data)

        return Response(serializer.data, status=status.HTTP_200_OK)

