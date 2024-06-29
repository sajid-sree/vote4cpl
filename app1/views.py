from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
import random
import string
import requests
import json
import datetime

def validate_username(uname):
    #check all username validations
    if User.objects.filter(username=uname).exists():
        return False
    return True


def validate_email(email):
    #check all email validations
    if User.objects.filter(email=email).exists() and not email.endswith('@svrec.ac.in'):
        return False
    return True


def validate_password(pwd):
    if len(pwd) < 8:
        return False
    else:
        if pwd.isalnum():
            return False
        return True

@csrf_exempt
#function to retun json data(json request and response)
def validate_details(request):
    if request.method == 'POST':
        uname = request.POST['username']
        email = request.POST['email']
        pwd = request.POST['password']
        if validate_username(uname) and validate_email(email) and validate_password(pwd):
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'failed'})
    else:
        return JsonResponse({'status': 'failed'})


def register_user(request):
    if request.method == 'POST':
        fname = request.POST['fname']
        lname = request.POST['lname']
        uname = request.POST['uname']
        email = request.POST['email']
        pwd = request.POST['pwd']
        if validate_username(uname) and validate_email(email) and validate_password(pwd):
            user = User.objects.create_user(username=uname, email=email, password=pwd, first_name=fname, last_name=lname, is_active=False)
            #send otp to user email
            user.save()
            code = ''.join(random.choices(string.digits, k=6))
            send_mail('OTP Code From vote4CPL',
                      'Welcome to Vote4CPL,  ' + code + ' is your verification code for Signup',
                      settings.EMAIL_HOST_USER,
                      [email], fail_silently=False)
            messages.success(request, 'Account created successfully, Please verify your email')
            request.session['otp'] = code
            return redirect('verify', username=uname)
        else:
            messages.error(request, 'Invalid Details')
            return redirect('register')
    else:
        messages.error(request, 'Invalid Request')
        return render(request, 'register.html')
def home(request):
    return render(request, 'home.html')


def loginView(request):
    return render(request, 'login.html')

def verify(request, username):
    if request.method == 'POST':
        otp = request.POST['otp']
        if otp == request.session['otp']:
            user = User.objects.get(username=username)
            user.is_active = True
            user.save()
            messages.success(request, 'Account Verified Successfully')
            return JsonResponse({'status': 'success'})
        else:
            messages.error(request, 'Invalid OTP')
            return JsonResponse({'status': 'failed'})
    else:
        return render(request, 'otp.html', {'username': username})

#window.location.href = "{% url 'login' %}";&location.reload();
def register(request):
    return render(request, 'register.html')
