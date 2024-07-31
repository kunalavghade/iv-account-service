from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status, views 
from rest_framework_simplejwt.tokens import RefreshToken 
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import  PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import jwt

from .serializers import RegisterSerializer, EmailVarificationSerializer, LoginSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
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
        
        Util.send_email(data)

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
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_str(user.id).encode('utf-8'))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'subject': 'Reset your passsword'}
            
            Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id = id)

            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                return Response({'error': 'Token is not valid, please requests a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message': 'Credential valid', 'uidb64': uidb64, 'token':token}, status=status.HTTP_200_OK)
            
        except DjangoUnicodeDecodeError as error:
             if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please requests a new one'}, status=status.HTTP_401_UNAUTHORIZED)
             

class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)

