import re
import jwt
import pyotp
import datetime
from twilio.rest import Client
from django.conf import settings
from django.core.mail import EmailMessage
from django.contrib.auth import get_user_model

User = get_user_model()
secret = getattr(settings, "JWT_SECRET", "e6212459c3b9d354e257215fd665429c185")
totp_secret = getattr(settings, "TOTP_SECRET",
                      "ae0d766a7ea543c35fe83c0f7d9a252")
algorithm = getattr(settings, "JWT_ALGORITHM", "HS256")


def send_email(to, subject=None, message=None):
    email = EmailMessage(
        subject,
        message,
        'hello@udyself.com',
        [to],
        ['bcc@example.com']
    )
    email.send()


def generate_access_token(user):
    access_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=getattr(settings, "JWT_EXPIRE_TIME", 1)),
        'iat': datetime.datetime.utcnow(),
    }

    access_token = jwt.encode(access_token_payload,
                              secret, algorithm=algorithm)
    return access_token


def generate_refresh_token(user):
    refresh_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2),
        'iat': datetime.datetime.utcnow()
    }

    refresh_token = jwt.encode(
        refresh_token_payload, secret, algorithm=algorithm)
    return refresh_token


def validate_password(password):
    if len(password) > 8:
        return False

    regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
    pattern = re.compile(regex)
    match = re.search(pattern, password)
    return match


def generate_email_verification(user, *args, **kwargs):
    expire_at = datetime.datetime.now() + datetime.timedelta(hours=2)
    payload = {'email': user.email, 'exp': expire_at}
    token = jwt.encode(payload, secret, algorithm=algorithm)

    return token


def verify_email_token(token, *args, **kwargs):
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        email, exp = payload['email'], payload['exp']

        user = User.objects.filter(email=email).first()
        if user is None:
            return False, None
    except (ValueError, jwt.DecodeError, jwt.ExpiredSignatureError):
        return False, None
    return True, user


def generate_otp():
    totp = pyotp.TOTP(s=totp_secret, digits=6, digest="SHA1", interval=75)
    return totp


def send_mobile_otp(mobile):
    twilio_mobile = getattr(settings, "TWILIO_MOBILE", None)
    account_sid = getattr(settings, "TWILIO_ACCOUNT", None)
    auth_token = getattr(settings, "TWILIO_TOKEN", None)

    client = Client(account_sid, auth_token)
    totp = generate_otp()
    message = f"OTP: {totp.now()}"

    response = client.messages.create(
        to=mobile, from_=twilio_mobile, body=message)
    return response
