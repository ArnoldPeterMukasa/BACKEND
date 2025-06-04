from rest_framework import generics, permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import Group
from django.contrib import messages
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.db.models import Q, Count
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.timezone import now
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
from .models import Issue, Notification, AssignedIssues
from .serializers import *
from .permissions import IsStudent, IsLecturer, IsRegistrar
from .utils import send_issue_assignment_email

user = get_user_model()


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

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all() #optional but a good practice
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny] #defines a serializer for the user registration

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# ... other imports like Issue model and IssueSerializer ...

class RegistrarDashboardView(APIView):
    def get(self, request, *args, **kwargs):
        # Get filter parameters
        course_param = request.query_params.get('course')
        status_param = request.query_params.get('status')
        
        # Base queryset: issues relevant to the registrar (could be all issues or filtered by permissions)
        issues_qs = Issue.objects.all()
        if course_param:
            issues_qs = issues_qs.filter(course_id=course_param)
        if status_param:
            if status_param.lower() == 'unresolved':
                # Filter for issues that are not resolved (unresolved issues)
                issues_qs = issues_qs.filter(~Q(status='Resolved'))
            else:
                # Filter by the exact status
                issues_qs = issues_qs.filter(status=status_param)
        
        # Calculate metrics on the filtered queryset
        total_issues = issues_qs.count()
        unresolved_issues = issues_qs.filter(~Q(status='Resolved')).count()
        
        # Average resolution time for resolved issues
        resolved_issues = issues_qs.filter(status='Resolved')
        if resolved_issues.exists():
            total_res_seconds = 0
            for issue in resolved_issues:
                # assuming Issue has a 'resolved_at' DateTimeField
                resolution_duration = issue.resolved_at - issue.created_at
                total_res_seconds += resolution_duration.total_seconds()
            avg_seconds = total_res_seconds / resolved_issues.count()
            avg_resolution_time = timedelta(seconds=avg_seconds)
        else:
            avg_resolution_time = timedelta(0)
        
        # Overdue issues: unresolved and created before a certain cutoff (e.g., 7 days ago)
        cutoff_date = now() - timedelta(days=7)
        overdue_issues_count = issues_qs.filter(~Q(status='Resolved'), created_at__lt=cutoff_date).count()
        
        # Serialize the filtered issues list
        serialized_issues = IssueSerializer(issues_qs, many=True).data
        
        # Prepare response data
        data = {
            "total_issues": total_issues,
            "unresolved_issues": unresolved_issues,
            "avg_resolution_time": str(avg_resolution_time),
            "overdue_issues_count": overdue_issues_count,
            "issues": serialized_issues
        }
        return Response(data)



#class StudentDashboardView(APIView):
#    authentication_classes = [JWTAuthentication]
#    permission_classes = [IsStudent]
#
#    def get(self, request):
#        try:
#            student = request.user
#
#            # add reistration  number to student info
#            student_info = {
#                'name': f"{student.first_name} {student.last_name}",
#                'email': student.email,
#                'registration_number': student.registration_number,
#                'course': student.course,
#                #'program': getattr(student, 'program', 'N/A')
#            }
#            try:
#                issues = Issue.objects.filter(reported_by=student)
#
#                #filter handling
#                status_filter = request.query_params.get('status')
#                category = request.query_params.get('category')
#                date_range = request.query_params.get('date_range')
#
#                if status_filter and status_filter.lower() != 'all':
#                    issues = issues.filter(status=status_filter)
#                if category:
#                    issues = issues.filter(category=category)
#                if date_range:
#                    # Add date range filtering logic if needed
#                    pass
#
#                # Analytics
#                analytics = {
#                    'totalIssues': issues.count(),
#                    'resolvedIssues': issues.filter(status='resolved').count(),
#                    'pendingIssues': issues.filter(status='pending').count(),
#                    'inProgressIssues': issues.filter(status='in_progress').count(),
#                    'recentActivity': issues.filter(
#                        updated_at__gte=datetime.now() - timedelta(days=7)
#                    ).count()
#                }
#
#                # Notifications
#                notifications = Notification.objects.filter(user=student, is_read=False)
#
#                return Response({
#                    'status': 'success',
#                    'student': student_info,
#                    'analytics': analytics,
#                    'issues': IssueSerializer(issues, many=True).data,
#                    'notifications': NotificationSerializer(notifications, many=True).data,
#                    'filters': {
#                        'statuses': ['open', 'in_progress', 'resolved', 'pending', 'all'],
#                        'categories': ['missing_marks', 'appeal', 'correction', 'other'],
#                        'dateRanges': ['today', 'week', 'month', 'all']
#                    }
#                }, status=status.HTTP_200_OK)
#
#            except Issue.DoesNotExist:
#                return Response({
#                    'status': 'error',
#                    'message': 'No issues found for the student.'
#                }, status=status.HTTP_404_NOT_FOUND)
#            
#        except Exception as e:
#            return Response({
#                'status': 'error',
#                'message': f"An unexpected error occurred: {str(e)}"
#            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class StudentDashboardView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsStudent]
    
    def get(self, request):
        try:
            student = request.user
            
            # Create student info dictionary with the required fields
            student_info = {
                'name': f"{student.first_name} {student.last_name}",
                'email': student.email,
                'registration_number': student.registration_number,
                'course': student.course,
                # 'program': getattr(student, 'program', 'N/A')
            }
            
            # Debug print to check student info
            print(f"Student info: {student_info}")
            
            try:
                issues = Issue.objects.filter(reported_by=student)
                
                # Filter handling
                status_filter = request.query_params.get('status')
                category = request.query_params.get('category')
                date_range = request.query_params.get('date_range')
                
                if status_filter and status_filter.lower() != 'all':
                    issues = issues.filter(status=status_filter)
                if category:
                    issues = issues.filter(category=category)
                if date_range:
                    # Add date range filtering logic if needed
                    pass
                
                # Analytics
                analytics = {
                    'totalIssues': issues.count(),
                    'resolvedIssues': issues.filter(status='resolved').count(),
                    'pendingIssues': issues.filter(status='pending').count(),
                    'inProgressIssues': issues.filter(status='in_progress').count(),
                    'recentActivity': issues.filter(
                        updated_at__gte=datetime.now() - timedelta(days=7)
                    ).count()
                }
                
                # Notifications
                notifications = Notification.objects.filter(user=student, is_read=False)
                
                return Response({
                    'status': 'success',
                    'student': student_info,
                    'analytics': analytics,
                    'issues': IssueSerializer(issues, many=True).data,
                    'notifications': NotificationSerializer(notifications, many=True).data,
                    'filters': {
                        'statuses': ['open', 'in_progress', 'resolved', 'pending', 'all'],
                        'categories': ['missing_marks', 'appeal', 'correction', 'other'],
                        'dateRanges': ['today', 'week', 'month', 'all']
                    }
                }, status=status.HTTP_200_OK)
            
            except Issue.DoesNotExist:
                return Response({
                    'status': 'success',
                    'student': student_info,
                    'message': 'No issues found for the student.',
                    'issues': [],
                    'notifications': [],
                    'analytics': {
                        'totalIssues': 0,
                        'resolvedIssues': 0,
                        'pendingIssues': 0,
                        'inProgressIssues': 0,
                        'recentActivity': 0
                    },
                    'filters': {
                        'statuses': ['open', 'in_progress', 'resolved', 'pending', 'all'],
                        'categories': ['missing_marks', 'appeal', 'correction', 'other'],
                        'dateRanges': ['today', 'week', 'month', 'all']
                    }
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f"An unexpected error occurred: {str(e)}"
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


class LecturerListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        lecturers = User.objects.filter(user_type='lecturer')
        serializer = UserSerializer(lecturers, many=True)
        return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_lecturers(request):
    lecturers = User.objects.filter(user_type = 'lecturer')
    serializer = UserSerializer(lecturers,many = True)
    return Response(serializer.data)

    
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

class RegistrarIssueListView(APIView):
    permission_classes = [IsAuthenticated, IsRegistrar]

    def get(self, request):
        issues = Issue.objects.all().order_by('-created_at')
        serialized = IssueSerializer(issues, many=True)
        return Response({'status': 'success', 'issues': serialized.data})

#class AssignIssueView(APIView):
#    permission_classes = [IsAuthenticated, IsRegistrar]
#    
#    def send_email_to_lecturer(self, lecturer, issue):
#        """Send an email notification to the lecturer about the new issue."""
#        subject = f"New Issue assigned: {issue.title}"
#        message = f"""
#        Hello {lecturer.get_full_name()},
#        
#        A new issue has been reported by {issue.reported_by.get_full_name()}.
#        
#        Issue Details:
#        Title: {issue.title}
#        Description: {issue.description}
#        
#        Please review this issue at your earliest convenience.
#        
#        Best regards,
#        System Administrator
#        """
#        
#        from_email = settings.DEFAULT_FROM_EMAIL
#        recipient_list = [lecturer.email]
#        
#        try:
#            send_mail(
#                subject=subject,
#                message=message,
#                from_email=from_email,
#                recipient_list=recipient_list,
#                fail_silently=False
#            )
#            return True
#        except Exception as e:
#            # Log the error but don't stop the process
#            print(f"Error sending email: {str(e)}")
#            return False
#    
#    def patch(self, request, pk):
#        
#        lecturer_username = request.data.get('lecturer_username')
#        lecturer = User.objects.get(username=lecturer_username, user_type='lecturer')
#        
#        issue = get_object_or_404(Issue, pk=pk)
#
#        try:
#            lecturer = User.objects.get(username=lecturer_username, user_type='lecturer')
#            issue.assigned_to = lecturer
#            issue.status = 'assigned'
#            self.send_email_to_lecturer(lecturer)
#            issue.save()
#            return Response({'message': 'Issue assigned successfully'}, status=200)
#        except User.DoesNotExist:
#            return Response({'error': 'Lecturer not found'}, status=400)    

class AssignIssueView(APIView):
    permission_classes = [IsAuthenticated, IsRegistrar]
    
    def send_email_to_lecturer(self, lecturer, issue):
        """Send an email notification to the lecturer about the new issue."""
        subject = f"New Issue assigned: {issue.title}"
        message = f"""
        Hello {lecturer.get_full_name()},
        
        A new issue has been reported by {issue.reported_by.get_full_name()}.
        
        Issue Details:
        Title: {issue.title}
        Description: {issue.description}
        
        Please review this issue at your earliest convenience.
        
        Best regards,
        System Administrator
        """
        
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [lecturer.email]
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False
            )
            return True
        except Exception as e:
            # Log the error but don't stop the process
            print(f"Error sending email to lecturer: {str(e)}")
            return False
    
    def send_email_to_student(self, student, issue, lecturer):
        """Send an email notification to the student who reported the issue."""
        subject = f"Your Issue has been assigned: {issue.title}"
        message = f"""
        Hello {student.get_full_name()},
        
        Your reported issue has been assigned to {lecturer.get_full_name()}.
        
        Issue Details:
        Title: {issue.title}
        Description: {issue.description}
        Status: Assigned
        
        You will receive updates as the issue progresses.
        
        Best regards,
        System Administrator
        """
        
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [student.email]
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False
            )
            return True
        except Exception as e:
            # Log the error but don't stop the process
            print(f"Error sending email to student: {str(e)}")
            return False
    
    def patch(self, request, pk):
        try:
            lecturer_username = request.data.get('lecturer_username')
            if not lecturer_username:
                return Response({'error': 'Lecturer username is required'}, status=400)
                
            issue = get_object_or_404(Issue, pk=pk)
            student = issue.reported_by
            
            try:
                lecturer = User.objects.get(username=lecturer_username, user_type='lecturer')
                
                # Update issue details
                issue.assigned_to = lecturer
                issue.status = 'assigned'
                issue.save()
                
                # Send email notifications
                lecturer_email_sent = self.send_email_to_lecturer(lecturer, issue)
                student_email_sent = self.send_email_to_student(student, issue, lecturer)
                
                response_data = {
                    'message': 'Issue assigned successfully',
                    'lecturer_email_sent': lecturer_email_sent,
                    'student_email_sent': student_email_sent
                }
                
                return Response(response_data, status=200)
            except User.DoesNotExist:
                return Response({'error': 'Lecturer not found'}, status=404)
                
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=500)


#class AssignIssueView(APIView):
#    permission_classes = [IsAuthenticated, IsRegistrar]
#    
#    def send_email_to_lecturer(self, lecturer, issue):
#        """Send an email notification to the lecturer about the new issue."""
#        subject = f"New Issue assigned: {issue.title}"
#        message = f"""
#        Hello {lecturer.get_full_name()},
#        
#        A new issue has been reported by {issue.reported_by.get_full_name()}.
#        
#        Issue Details:
#        Title: {issue.title}
#        Description: {issue.description}
#        
#        Please review this issue at your earliest convenience.
#        
#        Best regards,
#        System Administrator
#        """
#        
#        from_email = settings.DEFAULT_FROM_EMAIL
#        recipient_list = [lecturer.email]
#        
#        try:
#            send_mail(
#                subject=subject,
#                message=message,
#                from_email=from_email,
#                recipient_list=recipient_list,
#                fail_silently=False
#            )
#            return True
#        except Exception as e:
#            # Log the error but don't stop the process
#            print(f"Error sending email: {str(e)}")
#            return False
#    
#    def patch(self, request, pk):
#        try:
#            lecturer_username = request.data.get('lecturer_username')
#            if not lecturer_username:
#                return Response({'error': 'Lecturer username is required'}, status=400)
#                
#            issue = get_object_or_404(Issue, pk=pk)
#            
#            try:
#                lecturer = User.objects.get(username=lecturer_username, user_type='lecturer')
#                
#                # Update issue details
#                issue.assigned_to = lecturer
#                issue.status = 'assigned'
#                issue.save()
#                
#                # Send email notification
#                email_sent = self.send_email_to_lecturer(lecturer, issue)
#                
#                response_data = {
#                    'message': 'Issue assigned successfully',
#                    'email_sent': email_sent
#                }
#                
#                return Response(response_data, status=200)
#            except User.DoesNotExist:
#                return Response({'error': 'Lecturer not found'}, status=404)
#                
#        except Exception as e:
#            return Response({'error': f'An error occurred: {str(e)}'}, status=500)
# Create and List Issues
#class IssueListCreateView(generics.ListCreateAPIView):
#    queryset = Issue.objects.all()
#    serializer_class = IssueSerializer
#    authntication_classes = [JWTAuthentication] 
#    permission_classes = [permissions.IsAuthenticated, IsStudent] # Only Students can access
#
#    def get_queryset(self): # Only return issues created by the current student
#        return Issue.objects.filter(reported_by=self.request.user)
#
#
#    def perform_create(self, serializer):
#        try:
#            # Get the registrar who will be assigned to the issue
#            registrar = User.objects.filter(user_type='registrar').first()
#
#            if not registrar:
#                raise serializers.ValidationError("No registrar found to assign the issue.")
#
#                
#            # Save the issue with the current student as reported_by
#            issue = serializer.save(
#                reported_by=self.request.user,
#                assigned_to=registrar
#            )
#
#            # Create a notification for the registrar
#            Notification.objects.create(
#                user=registrar,
#                issue=issue,
#                message=f"New issue reported by {self.request.user.get_full_name()} - {issue.title}"
#            )
#
#        except Exception as e:
#            raise serializers.ValidationError(f"Error creating issue: {str(e)}")
#


class IssueListCreateView(generics.ListCreateAPIView):
    queryset = Issue.objects.all()
    serializer_class = IssueSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated, IsStudent]  # Only Students can access
    
    def get_queryset(self):  # Only return issues created by the current student
        return Issue.objects.filter(reported_by=self.request.user)
    
    def send_email_to_registrar(self, registrar, issue):
        """Send an email notification to the registrar about the new issue."""
        subject = f"New Issue Reported: {issue.title}"
        message = f"""
        Hello {registrar.get_full_name()},
        
        A new issue has been reported by {issue.reported_by.get_full_name()}.
        
        Issue Details:
        Title: {issue.title}
        Description: {issue.description}
        
        Please review this issue at your earliest convenience.
        
        Best regards,
        System Administrator
        """
        
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [registrar.email]
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False
            )
            print('____________________________________')
            print(registrar.email)
            print('____________________________________')
            return True
        except Exception as e:
            # Log the error but don't stop the process
            print(f"Error sending email: {str(e)}")
            return False
    
    def perform_create(self, serializer):
        try:
            # Get the registrar who will be assigned to the issue
            registrar = User.objects.filter(user_type='registrar').first()
            
            if not registrar:
                raise serializers.ValidationError("No registrar found to assign the issue.")
            
            # Save the issue with the current student as reported_by
            issue = serializer.save(
                reported_by=self.request.user,
                assigned_to=registrar
            )
            
            # Create a notification for the registrar
            Notification.objects.create(
                user=registrar,
                issue=issue,
                message=f"New issue reported by {self.request.user.get_full_name()} - {issue.title}"
            )
            
            # Send email to the registrar
            self.send_email_to_registrar(registrar, issue)
            
        except Exception as e:
            raise serializers.ValidationError(f"Error creating issue: {str(e)}")




# List all issues (for lecturers)
@api_view(['GET'])
def lecturer_list(request):
    lecturers = User.objects.filter(user_type='lecturer')
    data = [{"username": l.username, "name": f"{l.first_name} {l.last_name}"} for l in lecturers]
    return Response(data)


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
class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
        
    @action(detail=True, methods=['patch'], url_path='mark-as-read')
    def mark_as_read(self, request, pk=None):
        notification = self.get_oject()
        notification.is_read = True
        notification.save()
        return Response({'status': 'mark as read'})



class StudentRegistrationView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # Disable authentication for this view
    def post(self,request):
        data = request.data 
        serializer = StudentRegistrationSerializer(data=data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            password = validated_data.pop('password')
            
            
            user = User(**validated_data)
            user.set_password(password)
            user.save()
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            verification_code = randint(10000,99999)
            verification,created = VerificationCode.objects.get_or_create(
                user = user,
                defaults={"code": verification_code})
            
            verification.code = verification_code
            #verification_code.created_at = timezone.now()
            verification.save()
            
          
            subject = 'Email Verification Code'
            message = f"Hello, your Verification code is: {verification_code}"
            recipient_email = data.get('email')

            email = EmailMessage(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [recipient_email]
            )

            email.send(fail_silently=False)
            

            return Response({
                "message": "User  Created Successfully",
                'data': validated_data,
                "tokens": {
                    "refresh": str(refresh),
                    "access": access_token
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)



@method_decorator(csrf_exempt, name='dispatch')
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = VerifyEmailSerializer(data=data)
        if serializer.is_valid():
            verification_code = serializer.validated_data.get('code')
            user_email = serializer.validated_data.get('email')
            
            try:
                user = User.objects.get(email=user_email)
            except User.DoesNotExist:
                return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

            try:
                verification = VerificationCode.objects.get(user=user, code=verification_code)
                
                if verification.is_verification_code_expired():
                    return Response({'error': 'Verification Code has expired..'}, status=status.HTTP_400_BAD_REQUEST)
                
                verification.is_code_verified = True
                verification.save()
                
                user.is_email_verified = True
                user.save()
                return Response({'Message': 'Email verified successfully...'}, status=status.HTTP_200_OK)
                
            except VerificationCode.DoesNotExist:
                return Response({'error': 'Verification Code does not exist..'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        data = request.data 
        serializer = UserRegistrationSerializer(data=data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            password = validated_data.pop('password')
            validated_data.pop('password_confirmation')
            
            user = User(**validated_data)
            user.set_password(password)
            user.save()
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            verification_code = randint(10000,99999)
            verification,created = VerificationCode.objects.get_or_create(
                user = user,
                defaults={"code": verification_code})
            
            verification.code = verification_code
            #verification_code.created_at = timezone.now()
            verification.save()
            
            subject = 'Email Verification Code'
            message = f"Hello, your Verification code is: {verification_code}"
            recipient_email = data.get('email')

            email = EmailMessage(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [recipient_email]
            )

            email.send(fail_silently=False)
            

            return Response({
                "message": "User  Created Successfully",
                'data': validated_data,
                "tokens": {
                    "refresh": str(refresh),
                    "access": access_token
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class AssignedIssuesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Assuming issues have a field like assigned_to that links to a User or Lecturer
        assigned_issues = Issue.objects.filter(assigned_to=request.user)
        serializer = IssueSerializer(assigned_issues, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ResolveIssueView(APIView):
    permission_classes = [IsAuthenticated]
    
    
    def patch(self, request, issue_id):  # Changed from put to patch
        try:
            issue = Issue.objects.get(id=issue_id, assigned_to=request.user)
            
            # Get data from request
            status_update = request.data.get('status')
            resolution_comment = request.data.get('resolution_comment', '')
            
            # Validate status
            if status_update not in dict(Issue.STATUS_CHOICES).keys():
                return Response({
                    'error': f'Invalid status. Valid choices: {dict(Issue.STATUS_CHOICES).keys()}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Update issue
            issue.status = status_update
            issue.resolution_comment = resolution_comment  # Make sure this field exists in your model
            # If we want to store resolution comments, we could add a field to the Issue model
            # issue.resolution_comment = resolution_comment  # Assuming this field exists
            
            issue.save()
            
            # Create notification for the student who reported the issue
            Notification.objects.create(
                user=issue.reported_by,
                message=f"Your issue '{issue.title}' has been updated to {issue.get_status_display()}",
                issue=issue
            )
            
            # Send email notification to the student who reported the issue
            self.send_status_update_email(issue, status_update, resolution_comment)
            
            # Return the updated issue
            serializer = IssueSerializer(issue)
            return Response({
                'status': 'success',
                'message': f"Issue status updated to {issue.get_status_display()}",
                'issue': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Issue.DoesNotExist:
            return Response({
                'status': 'error',
                'message': "Issue not found or you are not authorized to update it"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f"An unexpected error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def send_status_update_email(self, issue, new_status, resolution_comment):
        """
        Send an email notification to the student who reported the issue
        when the status is updated by a lecturer.
        """
        try:
            # Email subject
            subject = f"Update on your issue: {issue.title}"
            
            # Email message
            message = f"""
            Dear {issue.reported_by.get_full_name() or issue.reported_by.username},
            
            Your issue "{issue.title}" has been updated to status: {issue.get_status_display()}.
            
            """
            
            # Add resolution comment if provided
            if resolution_comment:
                message += f"""
                Comment from lecturer:
                {resolution_comment}
                
                """
            
            message += f"""
            You can check more details by logging into the system.
            
            Regards,
            {issue.assigned_to.get_full_name() or issue.assigned_to.username}
            """
            
            # Sender email (from settings)
            from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com')
            
            # Recipient email
            recipient_list = [issue.reported_by.email]
            
            # Send the email
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False,
            )
            
            return True
            
        except Exception as e:
            # Log the error but don't stop the status update process
            print(f"Failed to send email notification: {str(e)}")
            return False

