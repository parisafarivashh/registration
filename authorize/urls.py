from django.urls import path

from authorize.views import TokenController, RegisterView, ChangePasswordView, \
    ForgetPasswordView

urlpatterns = [
    path('login', TokenController.as_view(), name='login'),
    path('sign-up', RegisterView.as_view(), name='sign-up'),
    path('reset-password', ForgetPasswordView.as_view(), name='reset-password'),
    path('set-password', ChangePasswordView.as_view(), name='set-password'),
]
