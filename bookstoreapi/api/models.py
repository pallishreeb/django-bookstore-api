from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
import uuid

class MyUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class MyUser(AbstractBaseUser):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, unique=True)
    isAdmin = models.BooleanField(default=False)
    isActive = models.BooleanField(default=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    tillValid = models.DateTimeField(blank=True, null=True)
    isEmailVerified = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    objects = MyUserManager()

    def __str__(self):
        return self.email

class Book(models.Model):
    bookid = models.CharField(max_length=20, unique=True, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField()
    coverPic = models.ImageField(upload_to='cover_pics/')
    pdfFile = models.FileField(upload_to='pdfs/')
    price = models.DecimalField(max_digits=10, decimal_places=2)
    author = models.CharField(max_length=255)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.bookid:
            last_book = Book.objects.order_by('-id').first()
            if last_book:
                last_id = int(last_book.bookid) + 1
            else:
                last_id = 10001
            self.bookid = str(last_id)
        super(Book, self).save(*args, **kwargs)

    def __str__(self):
        return self.title

class Order(models.Model):
    orderID = models.CharField(max_length=20, unique=True, editable=False)
    userID = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    bookID = models.ForeignKey(Book, on_delete=models.CASCADE)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)
    isDelivered = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.orderID:
            last_order = Order.objects.order_by('-id').first()
            if last_order:
                last_id = int(last_order.orderID[2:]) + 1
            else:
                last_id = 1
            self.orderID = f'OR{last_id:04}'
        super(Order, self).save(*args, **kwargs)

    def __str__(self):
        return self.orderID

