from django.contrib import admin

from .models import Book, Order

class BookAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'price', 'createdAt')
    search_fields = ('title', 'author')
    list_filter = ('author', 'createdAt')
    ordering = ('-createdAt',)

admin.site.register(Book, BookAdmin)

class OrderAdmin(admin.ModelAdmin):
    list_display = ('orderID', 'userID', 'bookID', 'isDelivered', 'createdAt')
    search_fields = ('orderID', 'userID__email', 'bookID__title')
    list_filter = ('isDelivered', 'createdAt')
    ordering = ('-createdAt',)

admin.site.register(Order, OrderAdmin)
