from django.urls import path
from . import views 

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('password_reset/', views.password_reset_view, name='password_reset'),
    path('registro/', views.registro_view, name='registro'),
]