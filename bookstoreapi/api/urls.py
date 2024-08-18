from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, VerifyOTPView,ResendOTPView, LoginView, ForgotPasswordView, ResetPasswordView,ChangePasswordView, BookViewSet, OrderViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'books', BookViewSet)
router.register(r'orders', OrderViewSet)

# For viewsets like LoginView, ForgotPasswordView, and ResetPasswordView,
# ensure they inherit from appropriate viewsets, not APIView.
router.register(r'login', LoginView, basename='login')
router.register(r'verify-otp', VerifyOTPView, basename='verify-otp')
router.register(r'resend-otp', ResendOTPView, basename='resend-otp')
router.register(r'forgot-password', ForgotPasswordView, basename='forgot-password')
router.register(r'reset-password', ResetPasswordView, basename='reset-password')
router.register(r'change-password', ChangePasswordView, basename='change-password')
urlpatterns = [
    path('', include(router.urls)),
    # path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    # path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
]
