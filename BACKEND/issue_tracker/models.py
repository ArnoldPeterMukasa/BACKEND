# working models.py
# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from random import randint
from django.utils import timezone

# Custom User Model
class User(AbstractUser):
    USER_TYPES = [
        ('student', 'student'),
        ('lecturer', 'Lecturer'),
        ('registrar', 'Academic Registrar'),
    ]
    user_type = models.CharField(max_length=20, choices=USER_TYPES)
    department = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)  # Username field for user
    # Email field for user
    # Role-specific fields
    registration_number = models.CharField(max_length=50, blank=True, null=True)  # For students
    course = models.CharField(max_length=100, blank=True, null=True)  # For students
    lecturer_id = models.CharField(max_length=50, blank=True, null=True)  # For lecturers
    academic_title = models.CharField(max_length=100, blank=True, null=True)  # For Academic registrars
    program = models.CharField(max_length=100, blank=True, null=True)  

    def _str_(self):
        return f"{self.username} ({self.get_user_type_display()})"


# Issue Model
class Issue(models.Model):
    ISSUE_CATEGORIES = [
        ('missing_marks', 'Missing Marks'),
        ('appeal', 'Appeal'),
        ('correction', 'Correction'), ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
    ]
    
    title = models.CharField(max_length=255)
    description = models.TextField()
    category = models.CharField(max_length=20, choices=ISSUE_CATEGORIES)
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reported_issues')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='assigned_issues', null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def _str_(self):
        return f"{self.title} - {self.get_status_display()}"


# Comment Model
class Comment(models.Model):
    issue = models.ForeignKey(Issue, on_delete=models.CASCADE, related_name='comments')
    commented_by = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return f"Comment by {self.commented_by.username} on {self.issue.title}"


#  Notification Model
class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    issue = models.ForeignKey(Issue, on_delete=models.CASCADE, related_name='notifications', null=True, blank=True)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return f"Notification for {self.user.username} - Read: {self.is_read}"

class VerificationCode(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    code = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_code_verified = models.BooleanField(default=False)
    
    def is_verification_code_expired(self):
        expiration_time = self.created_at + timezone.timedelta(minutes=20)
        return timezone.now() > expiration_time
        
    @classmethod
    def resend_verification_code(cls,user):
        try:
            cls.objects.filter(user = user).delete()
    
            new_verification_code = randint(10000,99999)
            verification = cls.objects.create(user = user,code= new_verification_code)
        except Exception as e:
            return {'Error':e}

        try:
            subject = 'Email verification Code Resend..'
            message = f"Hello, your Verification code that has been resent is: {new_verification_code}"
            receipient_email= user.email
            send_mail(subject,message,settings.EMAIL_HOST_USER,[receipient_email],fail_silently=False)
        except Exception as e:
            return {'Error':e}
        
        return {'Message':'Email verification code resent successfully...'}
    
    def str(self):
        return f'Verification for {self.user.username} --- {self.code}'''
class Lecturer(models.Model):
    name = models.CharField(max_length=255)
    
    # Add other fields for lecturer details as necessary

    def _str_(self):
        return self.name

class AssignedIssues(models.Model):
    issue_name = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, default='assigned')  # For example, you could have different statuses
    assigned_to = models.ForeignKey('Lecturer', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def _str_(self):
        return self.issue_name