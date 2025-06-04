from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Issue, Comment, Notification, AssignedIssues
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *





User = get_user_model()
class AssignedIssueSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignedIssues
        fields = ['id', 'issue_name', 'description', 'status', 'assigned_to', 'created_at']

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','first_name','last_name', 'username', 'email', 'user_type', 'department']

# Issue Serializer
class IssueSerializer(serializers.ModelSerializer):
    reported_by = UserSerializer(read_only=True)  # Display user info
    #assigned_to = UserSerializer (read_only=True)  # Display user info
    class Meta:
        model = Issue
        fields = ['id','title', 'description', 'category', 'status', 'reported_by', 'assigned_to', 'created_at', 'updated_at']

# Comment Serializer
class CommentSerializer(serializers.ModelSerializer):
    commented_by = UserSerializer(read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'issue', 'commented_by', 'text', 'created_at']

# Notification Serializer
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields =['id', 'user', 'issue', 'message', 'is_read', 'created_at']

# User Registration Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    registration_number = serializers.CharField(required=False, allow_blank=True)
    course = serializers.CharField(required=False, allow_blank=True)
    lecturer_id = serializers.CharField(required=False, allow_blank=True)
    academic_title = serializers.CharField(required=False, allow_blank=True)
    first_name = serializers.CharField(required=True)  # Make first_name required
    last_name = serializers.CharField(required=True)   # Make last_name required
    program = serializers.CharField(required= False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'user_type', 'department',
            'first_name', 'last_name',
            'registration_number', 'course', 'lecturer_id', 'academic_title','program'
        ]

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            user_type=validated_data['user_type'],
            department=validated_data.get('department', None),
            registration_number=validated_data.get('registration_number', None),
            course=validated_data.get('course', None),
            lecturer_id=validated_data.get('lecturer_id', None),
            academic_title=validated_data.get('academic_title', None),
            first_name=validated_data.get('first_name'),  # Include first_name
            last_name=validated_data.get('last_name'),    # Include last_name
            program=validated_data.get('program',None),
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user

# User Login Serializer
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        from django.contrib.auth import authenticate
        from django.contrib.auth import get_user_model

        User = get_user_model()  # Use the custom user model

        # Debug print
        print(f"DEBUG: Attempting login with username: {data.get('username')}")

        # Authenticate user
        user = authenticate(username=data.get('username'), password=data.get('password'))

        if not user:
            # Check if the user exists in the database
            user_exists = User.objects.filter(username=data.get('username')).exists()
            if not user_exists:
                print(f"DEBUG: User with username '{data.get('username')}' does not exist.")
            else:
                # Fetch the user and check the password manually for debugging
                db_user = User.objects.get(username=data.get('username'))
                if not db_user.check_password(data.get('password')):
                    print(f"DEBUG: Password mismatch for username '{data.get('username')}'.")
                else:
                    print(f"DEBUG: Authentication failed for an unknown reason for username '{data.get('username')}'.")
            
            raise serializers.ValidationError({
                "non_field_errors": ["Invalid username or password"]
            })

        # Check if the user is active
        if not user.is_active:
            print(f"DEBUG: User with username '{data.get('username')}' is inactive.")
            raise serializers.ValidationError({
                "non_field_errors": ["User account is inactive"]
            })

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return {
            'token': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.user_type,
                'department': user.department
            }
        }

class VerifyEmailSerializer(serializers.Serializer):
    code = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)


class ResendVerificationCodeSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
class StudentRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ['id', 'first_name', 'last_name','program','password',
                  'email','user_type','department','registration_number','username',
                  'course']
        extra_kwargs = {
            'password': {'write_only': True, 'required': True},  # Password is required and write-only
            'email': {'required': True},  # Email is required
            'username': {'required': True},  # Username is required
            'first_name': {'required': True},  # First name is required
            'last_name': {'required': True},  # Last name is required
            'user_type':{'required':True},
            'program':{'required':True},
            'course':{'required':True},
            'department':{'required':True},
            'registration_number':{'required':True},
        }
        
        
  

    def validate(self, data):
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        user_type = data.get('user_type')
        program= data.get('program')
        registration_number = data.get("registration_number")
        course = data.get("course")
        department = data.get("department")
        last_name = data.get("last_name")
        first_name = data.get("first_name")
        

        # Check if username already exists
        # if username and User .objects.filter(username=username).exists():
        # raise serializers.ValidationError('Username already exists')
        

        # Ensure staff_id_or_student_no is an integer
        if registration_number is not None:
            try:
                registration_number = int(registration_number)
            except ValueError:
                raise serializers.ValidationError('Invalid student number or staff id must be an integer')
            
        if user_type not in dict(User .USER_TYPES):
            raise serializers.ValidationError("Invalid role selected")

        if user_type != 'student':
            raise serializers.ValidationError("Only students can register using this endpoint")
            

        
        # if registration_number and User .objects.filter(registration_number=registration_number).exists():
        # raise serializers.ValidationError('Student with this student number already exists')

        
        if '@' not in email or email.split('@')[1] != 'gmail.com':
            raise serializers.ValidationError('Only Gmail accounts are allowed...')
        
        # Check if email already exists
        # if email and User .objects.filter(email=email).exists():
        #     raise serializers.ValidationError("Email already exists")
        
        if len(password) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        

        
        return data

    def create(self, validated_data):
        # Remove password confirmation from validated data
        # validated_data.pop('password_confirmation')
        user = User (**validated_data)
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user