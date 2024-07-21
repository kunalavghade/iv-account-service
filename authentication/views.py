from rest_framework.generics import GenericAPIView
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework import status 



class RegisterView(GenericAPIView):

    serializer_class = RegisterSerializer 

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data

        return Response(user_data, status= status.HTTP_201_CREATED)

