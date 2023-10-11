# forget_pass, send_mail_registration, otp verify import 
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
import random
# send_mail_registration
def send_mail_registration(email, otp):
    subject = "Account Verification otp"
    message = f'hi your verify otp is :  {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)
    
    # forget_pass function and send gmail
def forget_pass(r):
    otp = random.randint(1111,9999)
    if r.method == 'POST':
        email = r.POST.get('email')
        send_mail_registration(email, otp)
        user = User.objects.get(email=email)
        if user:
            prof = Profile(user = user, otp = otp)
            prof.save()
        return redirect('verify_otp')

    return render(r, 'accounts/Forget_password.html')


# otp verify  function
def verify_otp(r):
    if r.method == 'POST':
        email = r.POST.get('email')
        password = r.POST.get('pass')
        otp = r.POST.get('otp')

        user = User.objects.get(email=email)
        if user:
            prof = Profile.objects.get(user = user)
            if prof.otp == otp:
                user.set_password(password)
                user.save()
                update_session_auth_hash(r, user)
                messages.warning(r, "User Password Changed.")
                return redirect('signin')
            else:
                messages.warning(r, "Otp not matched Try again.")
    return render(r, 'accounts/verify_otp.html')
