from rest_framework import serializers
from .models import MyUser, Book, Order
import random
from django.utils import timezone

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ['id', 'name', 'email', 'phone', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = MyUser.objects.create(
            name=validated_data['name'],
            email=validated_data['email'],
            phone=validated_data['phone'],
            isActive=True,
            isAdmin=False,
            isEmailVerified=False,
            otp=str(random.randint(100000, 999999)),
            tillValid=timezone.now() + timezone.timedelta(minutes=10)
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()  

class ChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    old_password = serializers.CharField(max_length=255)
    new_password = serializers.CharField(max_length=255)
    confirm_password = serializers.CharField(max_length=255)

#login serializer
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

#Reset password with email, password and otp
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(max_length=255)
    otp = serializers.CharField(max_length=6)

class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = '__all__'

class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'
