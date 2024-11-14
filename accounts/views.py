from django.shortcuts import render
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.request import Request
from .serializer import *
from .utils import *
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator



class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request:Request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            send_code_to_user(user['email'])
            return Response({
                'data': user,
                'message': f"Hi, {user['first_name']} {user['last_name']} thanks for signing up a passcode has been sent to {user['email']}"
            }, status=status.HTTP_201_CREATED)
        return Response({
            "message": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyUserEmailView(GenericAPIView):
    def post(self, request:Request):
        otp_code = request.data.get('otp')
        try:
            user_code = OneTimePassword.objects.get(code=otp_code)
            user = user_code.user
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()
                return Response({
                    "message": "Email has been verified successfully"
                }, status=status.HTTP_200_OK)
            return Response({
                "message": "Email has already been verified"
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist:
            return Response({
                "message": "Invalid One Time Passcode Provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
class UserLoginView(GenericAPIView):
    serializer_class = UserLoginSerializer
    def post(self, request:Request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({
            "message": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
class TestView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request:Request):
        return Response({
            "message": "You are authenticated"
        }, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request:Request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            return Response({
                "message": "Passcode has been sent to your email to reset your password"
            }, status=status.HTTP_200_OK)
        return Response({
            "message": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetPasswordConfirmView(GenericAPIView):
    def get(self, request:Request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({"message": "Token is invalid or has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({
                "success": True, 
                "message": "Token is valid", 
                "uidb64": uidb64, 
                "token": token, 
                }, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError or User.DoesNotExist:
            return Response({"message": "Token is invalid or has expired"}, status=status.HTTP_400_BAD_REQUEST)
        

class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request:Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({
            "message": "Password has been reset successfully"
        }, status=status.HTTP_200_OK)