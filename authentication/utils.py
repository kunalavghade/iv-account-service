from django.core.mail import EmailMessage
from django.conf import settings

class Util:
    
    @staticmethod 
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body = data['email_body'],
            to = [data['to_email']],
            from_email = settings.EMAIL_HOST_USER
        )
        email.send()
