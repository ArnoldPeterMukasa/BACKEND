# Description: This file contains the views for the issue_tracker app.
from rest_framework import generics, permissions,status,serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Issue, Notification
from .serializers import UserSerializer, RegisterSerializer, LoginSerializer, IssueSerializer, NotificationSerializer
from .permissions import IsStudent, IsLecturer, IsRegistrar
from django.db.models import Q
from datetime import timedelta, datetime
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.timezone import now

User = get_user_model()

class RequestPasswordResetView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=400)

        try:
            user = User.objects.get(email=email)
            # Generate reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Send reset link via email
            reset_link = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
            subject = "Password Reset Request"
            message = f"Hello {user.first_name},\n\nClick the link below to reset your password:\n\n{reset_link}\n\nIf you didn't request this, you can ignore this email."
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

            return Response({"message": "Password reset email sent successfully"}, status=200)
        except User.DoesNotExist:
            return Response({"error": "No user found with this email"}, status=404)

class ResetPasswordConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            # Decode the user ID
            user_id = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=user_id)

            # Verify the token
            if not default_token_generator.check_token(user, token):
                return Response({"error": "Invalid or expired token"}, status=400)

            # Set new password
            new_password = request.data.get("new_password")
            if not new_password:
                return Response({"error": "New password is required"}, status=400)

            user.set_password(new_password)
            user.save()
            return Response({"message": "Password reset successful"}, status=200)
        except (User.DoesNotExist, ValueError):
            return Response({"error": "Invalid user or token"}, status=404)


#user registration
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all() #optional but a good practice
    serializer_class = RegisterSerializer #defines a serializer for the user registration

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RegistrarDashboardView(APIView):
    def get(self, request, *args, **kwargs):
        issues = Issue.objects.all()

        # Filter issues based on query parameters
        course = request.query_params.get('course')
        status = request.query_params.get('status')

        if course:
            issues = issues.filter(category=course)
        if status and status.lower() != 'all':
            issues = issues.filter(status=status)

        # Dashboard analytics
        total_issues = issues.count()
        unresolved_issues = issues.filter(~Q(status='resolved')).count()

        # Calculate average resolution time manually
        resolved_issues = issues.filter(status='resolved')
        if resolved_issues.exists():
            total_time = sum(
                (issue.updated_at - issue.created_at).total_seconds()
                for issue in resolved_issues
            )
            avg_resolution_time = total_time / resolved_issues.count()
            avg_resolution_time = timedelta(seconds=avg_resolution_time)
        else:
            avg_resolution_time = timedelta(0)

        # Overdue issues (open for more than 7 days)
        overdue_issues_count = issues.filter(
            Q(status='open') & Q(created_at__lte=now() - timedelta(days=7))
        ).count()

        data = {
            "total_issues": total_issues,
            "unresolved_issues": unresolved_issues,
            "avg_resolution_time": str(avg_resolution_time),
            "overdue_issues_count": overdue_issues_count,
        }
        return Response(data)
        
class StudentDashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsStudent]

    def get(self, request):
        try:
            student = request.user

            # Add registration number to student info
            student_info = {
                'name': f"{student.first_name} {student.last_name}",
                'email': student.email,
                'registration_number': student.registration_number,  # Add this field
                'course': student.course,
                'program': student.program  # Add this if available
            }

            # Query with error handling
            try:
                issues = Issue.objects.filter(reported_by=student)
                
                # Filter handling
                status = request.query_params.get('status')
                category = request.query_params.get('category')
                date_range = request.query_params.get('date_range')

                if status and status.lower() != 'all':
                    issues = issues.filter(status=status)
                if category:
                    issues = issues.filter(category=category)
                if date_range:
                    # Add date range filtering if needed
                    pass

                # Enhanced analytics
                analytics = {
                    'totalIssues': issues.count(),
                    'resolvedIssues': issues.filter(status='resolved').count(),
                    'pendingIssues': issues.filter(status='pending').count(),
                    'inProgressIssues': issues.filter(status='in_progress').count(),
                    'recentActivity': issues.filter(
                        updated_at__gte=datetime.now() - timedelta(days=7)
                    ).count()
                }

                return Response({
                    'status': 'success',
                    'student': student_info,
                    'analytics': analytics,
                    'issues': IssueSerializer(issues, many=True).data,
                    'notifications': NotificationSerializer(
                        Notification.objects.filter(user=student, is_read=False),
                        many=True
                    ).data,
                    'filters': {
                        'statuses': ['open', 'in_progress', 'resolved', 'pending', 'all'],
                        'categories': ['missing_marks', 'appeal', 'correction', 'other'],
                        'dateRanges': ['today', 'week', 'month', 'all']
                    }
                }, status=status.HTTP_200_OK)

            except Issue.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'No issues found for this student'
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class LecturerDashboardView(APIView):
    authentication_classes = [JWTAuthentication]  # Secure API with JWT
    permission_classes = [IsLecturer]  # Restrict access to lecturers only

    def get(self, request):
        # Fetch the logged-in lecturer
        lecturer = request.user

        # Query issues assigned to the lecturer
        issues = Issue.objects.filter(assigned_to=lecturer)

        # Apply filters from query parameters
        status = request.query_params.get('status')
        category = request.query_params.get('category')

        if status and status.lower() != 'all':
            issues = issues.filter(status=status)
        if category:
            issues = issues.filter(category=category)

        # Analytics for the lecturer
        total_issues = issues.count()
        resolved_issues = issues.filter(status='resolved').count()
        unresolved_issues = total_issues - resolved_issues

        # Fetch unread notifications for the lecturer
        notifications = Notification.objects.filter(user=lecturer, is_read=False)

        # Build and return the response
        return Response({
            'analytics': {
                'totalIssues': total_issues,
                'resolvedIssues': resolved_issues,
                'unresolvedIssues': unresolved_issues,
            },
            'issues': IssueSerializer(issues, many=True).data,
            'notifications': NotificationSerializer(notifications, many=True).data,
            'filters': {
                'statuses': ['open', 'in_progress', 'resolved', 'all'],
                'categories': list(Issue.objects.values_list('category', flat=True).distinct()),
            }
        })


    
#user login
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print(f"DEBUG: Received login request with data: {request.data}")
        
        serializer = LoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data
            print(f"DEBUG: Login successful")
            return Response({
                'token': validated_data['token'],
                'refresh': validated_data['refresh'],
                'role': validated_data['user']['role'],
                'user': validated_data['user']
            }, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            print(f"DEBUG: Validation error: {str(e)}")
            return Response(e.detail, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(f"DEBUG: Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
#Logout user
'''class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        print(f"DEBUG: Received login request with data: {request.data}")
        
        serializer = LoginSerializer(data=request.data)
        try:
            if serializer.is_valid():
                validated_data = serializer.validated_data
                print(f"DEBUG: Login successful for user: {validated_data['user']['username']}")
                return Response({
                    'token': validated_data['token'],
                    'refresh': validated_data['refresh'],
                    'role': validated_data['user']['role'],
                    'user': validated_data['user']
                }, status=status.HTTP_200_OK)
            else:
                print(f"DEBUG: Validation failed: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(f"DEBUG: Login exception: {str(e)}")
            return Response(
                {"error": "An error occurred during login"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )'''
    

# Get List of Users (for frontend to display user info)
class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsRegistrar] # Only Registrar can access

# Create and List Issues
class IssueListCreateView(generics.ListCreateAPIView):
    queryset = Issue.objects.all()
    serializer_class = IssueSerializer
    permission_classes = [permissions.IsAuthenticated, IsStudent] # Only Students can access

    def perform_create(self, serializer):
        serializer.save(reported_by=self.request.user)  # Assign current users as the reported_by

#  Retrieve, Update, and Delete an Issue
class IssueDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Issue.objects.all()
    serializer_class = IssueSerializer
    permission_classes = [permissions.IsAuthenticated, IsLecturer] # Only Lecturers can access

    def perform_update(self, serializer):
        issue = self.get_object()
        oldstatus = issue.status
        updated_issue = serializer.save()
        new_status = updated_issue.status
        
        #check if status has changes
        if oldstatus != new_status:
            student = updated_issue.reported_by
            subject = f"Issue '{updated_issue.title}' has been updated"
            message = f" hello {student.username},\n\n The status of your issue '{updated_issue.title}' has been updated to '{new_status}'."
            
            send_mail(subject, message, 'your_email@gmail.com', [student.email], fail_silently=False)
            
#  Get User Notifications
class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)


