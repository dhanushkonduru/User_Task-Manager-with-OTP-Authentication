from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from Myapp.views import UserViewSet, TaskViewSet, RegisterView, profile, UserList, TaskList, TaskDetail, login, generate_otp_and_send_sms

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'tasks', TaskViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', login, name='login'),
    path('api/users/', UserList.as_view(), name='user-list'),
    path('api/tasks/', TaskList.as_view(), name='task-list'),
    path('api/tasks/<int:pk>/', TaskDetail.as_view(), name='task-detail'),
    path('api/generate-otp/', generate_otp_and_send_sms, name='generate_otp'),  # Corrected import and usage
    path('api/users/generate-otp/', generate_otp_and_send_sms, name='generate_user_otp'),
    path('accounts/profile/', profile, name='profile'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]
