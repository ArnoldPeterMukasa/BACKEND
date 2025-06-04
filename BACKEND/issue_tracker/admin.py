
# Django admin configuration for the issue tracker application
# Register your models here.
from django.contrib import admin
from .models import User, Issue, Comment, Notification

admin.site.register(User)
admin.site.register(Issue)
admin.site.register(Comment)
admin.site.register(Notification) #register the Notification model with the admin site
