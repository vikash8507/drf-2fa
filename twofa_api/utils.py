from django.core.mail import EmailMessage


def send_email(to, subject=None, message=None):
    email = EmailMessage(
        subject,
        message,
        'hello@udyself.com',
        [to],
        ['bcc@example.com']
    )
    email.send()