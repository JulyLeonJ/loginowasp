import re
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.contrib import messages
import requests
from django import forms

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, label="Username")
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    turnstile_response = forms.CharField(widget=forms.HiddenInput())

def captcha_response(request):
        if request.method == 'POST':
            recaptcha_response = request.POST.get('g-recaptcha-response')
            if not recaptcha_response:
                messages.error(request, 'El reCAPTCHA es obligatorio.')
                return render(request, 'login.html', {'form': LoginForm()})
            
            secret_key = '6LcBLyIrAAAAAJL2-Cyx836qhqAj2vDXmjfhdfAm'  # Tu clave secreta
            data = {
                'secret': secret_key,
                'response': recaptcha_response
            }
            verify_url = 'https://www.google.com/recaptcha/api/siteverify'
            response = requests.post(verify_url, data=data)
            result = response.json()

            if not result.get('success'):
                messages.error(request, 'Error al verificar el reCAPTCHA. Inténtalo de nuevo.')
                return render(request, 'login.html', {'form': LoginForm()})


def login_view(request):
    if request.method == 'POST':
        captcha_result = captcha_response(request)
        if captcha_result:  
            return captcha_result
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')  
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

def registro_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Validar si el correo ya está registrado
        if User.objects.filter(email=email).exists():
            messages.error(request, 'El correo electrónico ya está registrado.')
            return render(request, 'registro.html')

        try:
            validate_password_strength(password)
        except forms.ValidationError as e:
            messages.error(request, e.message)
            return render(request, 'registro.html')
        
        # Crear el usuario
        user = User.objects.create_user(username=name, email=email, password=password)
        user.first_name = name
        user.save()
        messages.success(request, 'Registro exitoso. Ahora puedes iniciar sesión.')
        return redirect('login')

    return render(request, 'registro.html')

def password_reset_view(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            form.save(
                request=request,
                use_https=True,
                email_template_name='password_reset_email.html',
            )
            messages.success(request, 'Password reset email sent.')
            return redirect('login')
    else:
        form = PasswordResetForm()
    return render(request, 'password_reset.html', {'form': form})

def validate_password_strength(password):
    """
    Valida la fortaleza de una contraseña.
    Lanza una excepción ValidationError si no cumple con los criterios.
    """
    if len(password) < 8:
        raise forms.ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if not re.search(r'[A-Z]', password):
        raise forms.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
    if not re.search(r'[a-z]', password):
        raise forms.ValidationError("La contraseña debe contener al menos una letra minúscula.")
    if not re.search(r'[0-9]', password):
        raise forms.ValidationError("La contraseña debe contener al menos un número.")
    if not re.search(r'[@$!%*?&]', password):
        raise forms.ValidationError("La contraseña debe contener al menos un carácter especial (@, $, !, %, *, ?, &).")
