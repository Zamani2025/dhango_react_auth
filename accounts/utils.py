import random
from django.core.mail import EmailMessage
from .models import *
from django.conf import settings
def generateOtp():
    otp = ""
    for i in range(6):
        otp += str(random.randint(1, 9))
    return otp

def send_code_to_user(email):
    try:
        Subject = "One Time Password For Verification"
        otp = generateOtp()
        current_site = "mysite.com"
        user = User.objects.get(email=email)
        message = f"Hi {user.first_name}, Thanks for signing up on {current_site}. Your One Time Password is {otp}"
        from_email = settings.EMAIL_HOST_USER
        OneTimePassword.objects.create(user=user, code=otp)
        send_mail = EmailMessage(Subject, message, to=[email],from_email=from_email)
        send_mail.send(fail_silently=True)
    except Exception as e:
        print(e)

def send_normal_email(data):
    try:
        email = EmailMessage(
            subject=data['email_subject'], 
            body=data['email_body'], 
            from_email=settings.EMAIL_HOST_USER,
            to=[data['to_email']]
        )
        email.send(fail_silently=True)    
    except Exception as e:
        print(e)