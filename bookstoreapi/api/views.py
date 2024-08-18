from django.utils import timezone
from rest_framework.views import APIView
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from django.core.mail import send_mail
from django.conf import settings
from .models import MyUser, Book, Order
from .serializers import UserSerializer, BookSerializer, OrderSerializer, VerifyOTPSerializer, ResendOTPSerializer,LoginSerializer,ResetPasswordSerializer,ChangePasswordSerializer
import random
import jwt
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

class UserViewSet(viewsets.ModelViewSet):
    queryset = MyUser.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {user.otp}',
            'from@example.com',
            [user.email],
            fail_silently=False,
        )
        
        return Response({'message': 'User created successfully, OTP sent to email'}, status=status.HTTP_201_CREATED)

class VerifyOTPView(viewsets.ViewSet):
    serializer_class = VerifyOTPSerializer
    def create(self, request, *args, **kwargs):      
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            user = MyUser.objects.filter(email=email, otp=otp, tillValid__gte=timezone.now()).first()
            if user:
                user.isEmailVerified = True
                user.otp = ''
                user.tillValid = None
                user.save()
                return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)
            return Response({'message': 'Invalid OTP or OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(viewsets.ViewSet):
    serializer_class = ResendOTPSerializer
    def create(self, request, *args, **kwargs):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = MyUser.objects.filter(email=email).first()
            if user and not user.isEmailVerified:
                new_otp = str(random.randint(100000, 999999))
                user.otp = new_otp
                user.tillValid = timezone.now() + timezone.timedelta(minutes=10)
                user.save()

                send_mail(
                    'Your OTP Code',
                    f'Your new OTP code is {new_otp}',
                    'from@example.com',  # Replace with your sender email
                    [user.email],
                    fail_silently=False,
                )

                return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
            return Response({'message': 'Email not found or already verified.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(viewsets.ViewSet):
    serializer_class = LoginSerializer
    parser_classes = [JSONParser, FormParser, MultiPartParser]  # Allow handling of both JSON and form data

    def create(self, request, *args, **kwargs):
        # Validate the input data
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = MyUser.objects.filter(email=email).first()
            
            if user and user.check_password(password):
                if user.isEmailVerified:
                    token = jwt.encode({'email': user.email}, settings.SECRET_KEY, algorithm='HS256')
                    return Response({'token': token, 'message': 'Login successful'}, status=status.HTTP_200_OK)
                return Response({'message': 'Email not verified'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(viewsets.ViewSet):
    serializer_class = ResendOTPSerializer
    def create(self, request, *args, **kwargs):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = MyUser.objects.filter(email=email).first()
            if user:
                user.otp = str(random.randint(100000, 999999))
                user.tillValid = timezone.now() + timezone.timedelta(minutes=10)
                user.save()
                
                send_mail(
                    'Your OTP Code for Password Reset',
                    f'Your OTP code is {user.otp}',
                    'from@example.com',
                    [user.email],
                    fail_silently=False,
                )
                return Response({'message': 'OTP sent to email'}, status=status.HTTP_200_OK)
            return Response({'message': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

class ChangePasswordView(viewsets.ViewSet):
    # permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    def create(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            confirm_password = serializer.validated_data['confirm_password']

            user = MyUser.objects.filter(email=email).first()

            if not user.check_password(old_password):
                return Response({'message': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

            if new_password != confirm_password:
                return Response({'message': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(viewsets.ViewSet):
    serializer_class = ResetPasswordSerializer
    def create(self, request, *args, **kwargs):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            user = MyUser.objects.filter(email=email, otp=otp, tillValid__gte=timezone.now()).first()
            if user:
                user.set_password(new_password)
                user.otp = ''
                user.tillValid = None
                user.save()
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
            return Response({'message': 'Invalid OTP or OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

class BookViewSet(viewsets.ModelViewSet):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    http_method_names = ['get', 'post', 'put', 'delete']
    
    # Get all books
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    # Get book by bookid
    def retrieve(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        book = get_object_or_404(queryset, bookid=pk)
        serializer = self.get_serializer(book)
        return Response(serializer.data)

class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, FormParser, MultiPartParser]
    
    # Create a new order
    def create(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            order = serializer.save(userID=user)
            return Response(OrderSerializer(order).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Get all orders for the authenticated user
    def list(self, request, *args, **kwargs):
        user = request.user
        queryset = Order.objects.filter(userID=user)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    # Get order by orderID
    def retrieve(self, request, pk=None, *args, **kwargs):
        user = request.user
        order = get_object_or_404(Order, orderID=pk, userID=user)
        serializer = self.get_serializer(order)
        return Response(serializer.data)