from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from app1.models import vote
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
    if User.objects.filter(email=email).exists() or not email.endswith('@svrec.ac.in'):
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
            user = User.objects.create_user(username=uname, email=email, password=pwd, first_name=fname,
                                            last_name=lname, is_active=False)
            #send otp to user email
            user.save()
            code = ''.join(random.choices(string.digits, k=6))
            send_mail('OTP Code From vote4CPL',
                      'Welcome to Vote4CPL,  ' + code + ' is your verification code',
                      settings.EMAIL_HOST_USER,
                      [email], fail_silently=False)
            messages.success(request, 'Account created successfully, Please verify your email')
            request.session['otp'] = code
            return redirect('verify', username=uname)
        else:
            messages.error(request, 'Invalid Details')
            return redirect('register')
    else:

        return render(request, 'register.html')


def home(request):
    events = vote.objects.all()
    return render(request, 'home.html', {'events': events})


def loginView(request):
    if request.method == 'POST':
        uname = request.POST['username']
        pwd = request.POST['password']
        user = authenticate(username=uname, password=pwd)
        if user is not None:
            login(request, user)
            if user.is_superuser:
                return JsonResponse({'status': 'success', 'user': 'admin'})
            messages.success(request, 'Login Successful')
            return JsonResponse({'status': 'success', 'user': 'normal'})
        else:

            return JsonResponse({'status': 'failed'})
    else:
        return render(request, 'login.html')


def verify(request, username):
    if request.method == 'POST':
        otp = request.POST['otp']
        if otp == request.session['otp']:
            user = User.objects.get(username=username)
            user.is_active = True
            user.save()
            print('User Verified')
            messages.success(request, 'Account Verified Successfully')
            return JsonResponse({'status': 'success'})
        else:

            return JsonResponse({'status': 'failed'})
    else:
        return render(request, 'otp.html', {'username': username})


#window.location.href = "{% url 'login' %}";&location.reload();
def register(request):
    return render(request, 'register.html')


def logout_view(request):
    logout(request)
    messages.success(request, 'Logged Out Successfully')
    return redirect('login')


@login_required(login_url='login')
def create_event(request):
    if request.user.is_superuser:
        if request.method == 'POST':
            event = request.POST['event']
            candidate1 = request.POST['candidate1']
            candidate2 = request.POST['candidate2']
            description = request.POST['description']
            endtime = request.POST['endtime']
            vote.objects.create(Event=event, candidateName1=candidate1, candidateName2=candidate2,
                                description=description, endtime=endtime)
            messages.success(request, 'Event Created Successfully')
            return redirect('create')
        else:
            return render(request, 'create_event.html')
    else:
        messages.error(request, 'You are not authorized to create event')
        return redirect('home')


def resend_otp(request, username):
    code = ''.join(random.choices(string.digits, k=6))
    send_mail('OTP Code From vote4CPL',
              'Welcome to Vote4CPL,  ' + code + ' is your verification code',
              settings.EMAIL_HOST_USER,
              [User.objects.get(username=username).email], fail_silently=False)
    #messages.success(request, 'OTP Sent Successfully')
    request.session['otp'] = code
    return JsonResponse({'status': 'success'})


def forgot(request, username):
    if request.method == 'POST':
        otp = request.POST['otp']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        if otp == request.session['otp']:
            if pass1 == pass2:
                a = validate_password(pass1)
                b = validate_password(pass2)
                if a and b:
                    user = User.objects.get(username=username)
                    user.set_password(pass1)
                    user.save()
                    messages.success(request, 'Password Changed Successfully')
                    return JsonResponse({'status': 'success'})
                else:

                    return JsonResponse({'status': 'failed', 'message': 'Password is weak'})
            else:

                return JsonResponse({'status': 'failed', 'message': 'Passwords do not match'})
        else:

            return JsonResponse({'status': 'failed', 'message': 'Invalid OTP'})
    else:
        return render(request, 'forgot.html', {'username': username})


def vote_page(request, eventid):
    event = vote.objects.get(id=eventid)
    return render(request, 'vote.html', {'event': event})


def vote1(request, eventid):
    event = vote.objects.get(id=eventid)
    if request.method == 'GET':
        user = request.user
        if user.is_authenticated:

            if user in event.VotesCandidate2.all() or user in event.VotesCandidate1.all():
                messages.error(request, 'You have already voted')
                return render(request, 'vote.html', {'event': event})
            else:
                event.VotesCandidate1.add(user)
                messages.success(request, 'Vote Registered Successfully')
                return render(request, 'vote.html', {'event': event})
        else:
            messages.error(request, 'Login to vote')
            return redirect('login')
    else:
        return render(request, 'vote.html', {'event': event})


def vote2(request, eventid):
    event = vote.objects.get(id=eventid)
    if request.method == 'GET':
        user = request.user

        if user.is_authenticated:
            if user in event.VotesCandidate1.all() or user in event.VotesCandidate2.all():
                messages.error(request, 'You have already voted')
                return render(request, 'vote.html', {'event': event})
            else:
                event.VotesCandidate2.add(user)
                messages.success(request, 'Vote Registered Successfully')
                return render(request, 'vote.html', {'event': event})
        else:
            messages.error(request, 'Login to vote', {'event': event})
            return redirect('login')
    else:
        return render(request, 'vote.html', {'event': event})


def forgot_view(request):
    if request.method == 'POST':
        user = request.POST['uname']
        if User.objects.filter(username=user).exists():
            code = ''.join(random.choices(string.digits, k=6))
            send_mail('OTP Code From vote4CPL',
                      'Welcome to Vote4CPL,  ' + code + ' is your verification code',
                      settings.EMAIL_HOST_USER,
                      [User.objects.get(username=user).email], fail_silently=False)
            request.session['otp'] = code
            return redirect('forgot', username=user)
        else:
            messages.error(request, 'Invalid Username')
            return redirect('forgot_pass')
    else:
        return render(request, 'forgot_pass.html')
