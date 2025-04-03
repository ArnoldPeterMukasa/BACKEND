

# Register your models here.
from django.contrib import admin
from .models import User, Issue, Comment, Notification, AuditTrail

admin.site.register(User)
admin.site.register(Issue)
admin.site.register(Comment)
admin.site.register(Notification)
admin.site.register(AuditTrail)
