from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer, OwnerSerializer
from .models import Users
import pyotp


class OwnerRegistrationView(APIView):
    serializer_class = OwnerSerializer

    def post(self, request, format=None):
        serializer = OwnerSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({"status": "success", 'message': "Registered successfully, please login"},
                                status=status.HTTP_201_CREATED)
            except Exception as e:
                print(f"Exception occurred during save: {e}")
                return Response({"status": "fail", "message": "User with that email already exists"},
                                status=status.HTTP_409_CONFLICT)
        else:
            return Response({"status": "fail", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(generics.GenericAPIView):
    serializer_class = UserSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({"status": "success", 'message': "Registered successfully, please login"},
                                status=status.HTTP_201_CREATED)
            except Exception as e:
                print(f"Exception occurred during save: {e}")
                return Response({"status": "fail", "message": "User with that email already exists"},
                                status=status.HTTP_409_CONFLICT)
        else:
            return Response({"status": "fail", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = UserSerializer

    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')
        print("From login\n")
        user = authenticate(username=email.lower(), password=password)
        if user is None:
            return Response({"status": "fail", "message": "Incorrect email or password"},
                            status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({"status": "fail", "message": "Incorrect email or password"},
                            status=status.HTTP_400_BAD_REQUEST)

        if user.otp_verified:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            welcome_message = f"Welcome, {user.name}! Your account is already verified."
            return Response({"status": "success",
                             "message": welcome_message,
                             "access_token": access_token,
                             })

        # otp generation
        otp_base32 = pyotp.random_base32()
        user.secret_key = otp_base32
        user.save()
        serializer = self.serializer_class(user)
        return Response({"status": "success",
                         "user": serializer.data,
                         "secret_key": otp_base32,
                         "message:": "Please use the id and secret key to get the otp from Authy!"})


class VerifyOTP(generics.GenericAPIView):
    serializer_class = UserSerializer

    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = Users.objects.filter(id=user_id).first()
        if user is None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"},
                            status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.secret_key)
        if not totp.verify(otp_token):
            return Response({"status": "fail", "message": "Invalid Token"}, status=status.HTTP_400_BAD_REQUEST)

        user.otp_verified = True
        user.save()
        serializer = self.serializer_class(user)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({"message": "Your OTP has been verified. Now use the access token to enter a route",
                         "user": serializer.data,
                         "access_token:": access_token,
                         })


@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
class ProtectedView(APIView):
    def get(self, request):
        # Perform actions for authenticated users only
        user = request.user
        return Response({"message": f"Welcome {user.name}. This is protected route. Only accessible with Jwt token."})


@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
class PasswordResetFormView(APIView):

    def post(self, request):
        # Get data from the request
        new_password = request.data.get('new_password')

        # Get the authenticated user
        user = request.user

        # Update the user's password
        user.set_password(new_password)
        user.save()

        return Response({"message": f"{user.name} your password reset successful."}, status=status.HTTP_200_OK)


@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
class OwnerView(APIView):

    def get(self, request):
        if request.user.role == 'owner':
            customers = Users.objects.filter(role='general')
            serializer = UserSerializer(customers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "You don't have permission to access this view."}, status=status.HTTP_403_FORBIDDEN)
