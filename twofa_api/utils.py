import re
import jwt
import datetime
from django.conf import settings
from django.core.mail import EmailMessage
from django.contrib.auth import get_user_model

User = get_user_model()
secret = settings.SECRET_KEY
algorithm = "HS256"

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
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
        'iat': datetime.datetime.utcnow(),
    }
    access_token = jwt.encode(access_token_payload, settings.SECRET_KEY, algorithm='HS256').decode('utf-8')
    return access_token

def generate_refresh_token(user):
    refresh_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }
    refresh_token = jwt.encode(refresh_token_payload, settings.REFRESH_TOKEN_SECRET, algorithm='HS256').decode('utf-8')

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
