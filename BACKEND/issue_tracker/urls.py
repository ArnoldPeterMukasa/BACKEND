from django.urls import path
from .views import RegisterView, LoginView, StudentDashboardView, LecturerDashboardView, UserListView, IssueListCreateView, IssueDetailView, NotificationListView,RegistrarDashboardView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    #path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # Refresh token
    path('users/', UserListView.as_view(), name='user-list'),
    path('issues/', IssueListCreateView.as_view(), name='issue-list-create'),
    path('issues/<int:pk>/', IssueDetailView.as_view(), name='issue-detail'),
    path('notifications/', NotificationListView.as_view(), name='notification-list'),
    path('RegistrarDashboard/', RegistrarDashboardView.as_view(), name='registrar-dashboard'),
    #path('api/RegistrarDashboard/', RegistrarDashboardView.as_view(), name='registrar-dashboard'),
    path('dashboard/student/', StudentDashboardView.as_view(), name='student_dashboard'),
    path('dashboard/lecturer/', LecturerDashboardView.as_view(), name='lecturer_dashboard'),
        
]