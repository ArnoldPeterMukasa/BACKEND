from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Issue, Comment, Notification, AuditTrail
from rest_framework_simplejwt.tokens import RefreshToken


User = get_user_model()

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','first_name','last_name', 'username', 'email', 'user_type', 'department']

# Issue Serializer
class IssueSerializer(serializers.ModelSerializer):
    reported_by = UserSerializer(read_only=True)  # Display user info

    class Meta:
        model = Issue
        fields = ['id', 'description', 'category', 'status', 'reported_by', 'assigned_to', 'created_at', 'updated_at']

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

# Audit Trail Serializer
class AuditTrailSerializer(serializers.ModelSerializer):
    action_by = UserSerializer(read_only=True)

    class Meta:
        model = AuditTrail
        fields = ['id', 'issue', 'action_by', 'action_description', 'timestamp']

# User Registration Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    registration_number = serializers.CharField(required=False, allow_blank=True)
    course = serializers.CharField(required=False, allow_blank=True)
    lecturer_id = serializers.CharField(required=False, allow_blank=True)
    academic_title = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'user_type', 'department',
            'first_name', 'last_name',
            'registration_number', 'course', 'lecturer_id', 'academic_title'
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