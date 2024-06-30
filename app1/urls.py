from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.loginView, name='login'),
    path('signup/', views.register_user, name='register'),
    path('validate/', views.validate_details, name='validate'),
    #path('logout/', views.logoutView, name='logout'),
    path('verify/<str:username>/', views.verify, name='verify'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot/<str:username>/', views.forgot, name='forgot'),
    path('reset/<str:username>', views.resend_otp, name='reset'),
    path('create/', views.create_event, name='create'),
    path('vote/<int:eventid>', views.vote_page, name='vote'),
    path('vote1/<int:eventid>/', views.vote1, name='vote1'),
    path('vote2/<int:eventid>/', views.vote2, name='vote2'),
    path('forgot_pass/', views.forgot_view, name='forgot_pass'),

]