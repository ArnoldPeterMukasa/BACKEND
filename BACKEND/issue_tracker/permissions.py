from rest_framework import permissions

class IsStudent(permissions.BasePermission): #student permission
    def has_permission(self,request,view):
        return request.user.is_authenticated and request.user.user_type == 'student'

class IsLecturer(permissions.BasePermission):
    def has_permission(self,request,view):
        return request.user.is_authenticated and request.user.user_type == 'lecturer'

class IsRegistrar(permissions.BasePermission):
    def has_permission(self,request,view):
        return request.user.is_authenticated and request.user.user_type == 'registrar'

class CanAssignIssues(permissions.BasePermission):
    """Custom permission to only allow registrars to assign issues."""
    def has_permission(self, request, view):
        return request.user and request.user.user_type == 'registrar'        