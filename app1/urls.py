from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.loginView, name='login'),
    path('signup/', views.register_user, name='register'),
    path('validate/', views.validate_details, name='validate'),
    #path('logout/', views.logoutView, name='logout'),
    path('verify/<str:username>/', views.verify, name='verify'),
]