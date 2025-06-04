from django.urls import path, include
from .views import *  # * means u importing all from the views.py file
#UnassignedIssuesView, AssignIssueView
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.routers import DefaultRouter
router = DefaultRouter()
router.register(r'notifications', NotificationViewSet, basename='notifications')

urlpatterns = [
    
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('register_student/', StudentRegistrationView.as_view(), name='register_student'),
    #path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # Refresh token
    #path('users/', UserListView.as_view(), name='user-list'),
    path('create-issues/', IssueListCreateView.as_view(), name='issue-list-create'),
    path('issues/<int:pk>/', IssueDetailView.as_view(), name='issue-detail'),
    path('RegistrarDashboard/', RegistrarDashboardView.as_view(), name='registrar-dashboard'),
    path('studentDashboard/', StudentDashboardView.as_view(), name='student_dashboard'),
    path('dashboard/lecturer/', LecturerDashboardView.as_view(), name='lecturer_dashboard'),
    #path('issues/unassigned/', UnassignedIssuesView.as_view(), name='unassigned-issues'),
    #path('issues/<int:pk>/assign/', AssignIssueView.as_view(), name='assign-issue'), 
    path('RegistrarIssues/', RegistrarIssueListView.as_view(), name='registrar_issues'),
    path('issues/<int:pk>/assign/', AssignIssueView.as_view(), name='assign-issue'),
    path('issues/assigned/', AssignedIssuesView.as_view(), name='assigned-issues'),
    #path('lecturers/', LecturerListView.as_view(), name='lecturer-list'),
    path('lecturers/', get_lecturers, name='lecturer-list'),
    path('student_registration',StudentRegistrationView.as_view(), name='student_registration'),
    path('issues/resolve/<str:issue_id>/', ResolveIssueView.as_view(), name='resolve-issue'),

    path('', include(router.urls)),
]