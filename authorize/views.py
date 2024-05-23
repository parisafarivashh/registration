from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlencode
from django.utils.encoding import force_bytes
from rest_framework.views import APIView
from sendgrid import sendgrid, Mail

from registration import settings
from .models import User
from .serializers import DRFTokenSerializer, UserRegisterSerializer, \
    ChangePasswordSerializer, SendEmailSerializer


class TokenController(TokenObtainPairView):
    serializer_class = DRFTokenSerializer


class RegisterView(CreateAPIView):
    permission_classes = [AllowAny]
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer


class ChangePasswordView(UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    queryset = User.objects.all()

    def get_object(self):
        return User.objects.get(id=self.request.user.id)


class ForgetPasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SendEmailSerializer

    def post(self, request, *args, **kwargs):
        token = self.request.headers.get('Authorization')
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.filter(email=email)

        if not user.exists():
            error = {"email": ["User with this email does not exist"]}
            raise ValidationError(detail=error)

        base_url = f"{request.scheme}://{request.get_host()}"
        path = reverse('set-password')  # URL pattern name for your view
        query_string = urlencode({'Authorization': token})
        reset_url = f"{base_url}{path}?{query_string}"

        context = {
            'reset_url': reset_url,
            'user': user,
        }
        body = render_to_string('password_reset_email.html', context)
        self.send_email(body=body, to_email=email)
        return Response(
            data=dict(details='Email sent successfully'),
            status=status.HTTP_202_ACCEPTED
        )

    @staticmethod
    def send_email(body, to_email):
        message = Mail(
            from_email=settings.FROM_EMAIL,
            to_emails=[to_email],
            subject='Reset Password',
            html_content=body,
        )
        sg = sendgrid.SendGridAPIClient(api_key=settings.SENDER_GRID_API_KEY)
        response = sg.send(message)

        if response.status_code != 202:
            print(f"SendGrid error: {response.status_code} - {response.body}")

