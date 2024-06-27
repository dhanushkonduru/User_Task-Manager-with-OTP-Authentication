from rest_framework import viewsets, generics, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .models import Task, User
from .serializers import UserSerializer, TaskSerializer, RegisterSerializer, LoginSerializer
from rest_framework.exceptions import ValidationError
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .utils import generate_otp, send_otp_via_sms, generate_access_token
from rest_framework.views import APIView

class UserList(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class TaskList(generics.ListCreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer

class TaskDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = request.data["refresh_token"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response(status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def login(request):
    try:
        phone_number = request.data["phone_number"]
        country_code = request.data["country_code"]
        otp = request.data["otp"]

        user = User.objects.get(phone_number=phone_number, country_code=country_code)

        if user.otp != otp or timezone.now() > user.otp_created_at + timezone.timedelta(minutes=10):
            raise ValidationError("Invalid or expired OTP")

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    except ValidationError as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user_serializer = self.get_serializer(data=request.data)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()

        tasks_data = request.data.get('tasks', [])
        for task_data in tasks_data:
            task_data['user'] = user.id
            task_serializer = TaskSerializer(data=task_data)
            task_serializer.is_valid(raise_exception=True)
            task_serializer.save()

        headers = self.get_success_headers(user_serializer.data)
        return Response(user_serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        user_serializer = self.get_serializer(instance, data=request.data, partial=partial)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()

        tasks_data = request.data.get('tasks', [])
        task_ids = [task['id'] for task in tasks_data if 'id' in task]

        # Delete tasks that are not in the request
        for task in user.tasks.all():
            if task.id not in task_ids:
                task.delete()

        for task_data in tasks_data:
            task_id = task_data.get('id')
            if task_id:
                task_instance = Task.objects.get(id=task_id, user=user)
                task_serializer = TaskSerializer(task_instance, data=task_data, partial=partial)
            else:
                task_data['user'] = user.id
                task_serializer = TaskSerializer(data=task_data)
            task_serializer.is_valid(raise_exception=True)
            task_serializer.save()

        return Response(user_serializer.data)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

            otp = generate_otp()
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            phone_number = f"{user.country_code}{user.phone_number}"
            send_otp_via_sms(phone_number, otp)

            return Response({
                'message': 'User registered successfully. OTP sent to phone number.'
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Something went wrong'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@login_required  # Apply login_required decorator to your view function
def profile(request):
    return render(request, 'profile.html')

@api_view(['POST'])
def register_user(request):
    try:
        phone_number = request.data.get('phone_number')
        country_code = request.data.get('country_code')

        # Validate phone_number and country_code
        if not phone_number or not country_code:
            return Response({'error': 'Phone number and country code are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP
        otp = generate_otp()

        # Save OTP and OTP creation time in user instance (create or update as needed)
        user, created = User.objects.update_or_create(
            phone_number=phone_number,
            defaults={
                'country_code': country_code,
                'otp': otp,
                'otp_created_at': timezone.now()
            }
        )

        # Send OTP via SMS
        phone_with_code = f"{country_code}{phone_number}"
        if send_otp_via_sms(phone_with_code, otp):
            return Response({'message': 'OTP sent successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP via SMS.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def generate_otp_and_send_sms(request):
    try:
        phone_number = request.data["phone_number"]
        country_code = request.data["country_code"]

        user = User.objects.get(phone_number=phone_number, country_code=country_code)

        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        phone_with_code = f"{country_code}{phone_number}"
        send_otp_via_sms(phone_with_code, otp)

        return JsonResponse({'message': 'OTP generated and sent successfully.'}, status=200)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User does not exist.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data['phone']
        country_code = serializer.validated_data['country_code']
        otp = serializer.validated_data['otp']

        try:
            user = User.objects.get(phone_number=phone, country_code=country_code)
            if user.otp == otp and user.otp_created_at > timezone.now() - timezone.timedelta(minutes=10):
                access_token = generate_access_token(user)
                return Response({'access_token': access_token}, status=status.HTTP_201_CREATED)
            else:
                return Response({'detail': 'Invalid OTP or OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
