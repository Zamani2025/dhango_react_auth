from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

class UserManager(BaseUserManager):
    def email_validator(self, email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("You must provide a valid email address"))
        
    def create_user(self, email, first_name, last_name, password=None, **extra_fields):
        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(_("You must provide an email address"))
        
        if not first_name:
            raise ValueError(_("You must provide a first name"))
        
        if not last_name:
            raise ValueError(_("You must provide a last name"))

        user = self.model(email=email, first_name=first_name, last_name=last_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, first_name, last_name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        if extra_fields.get('is_active') is not True:
            raise ValueError(_('Superuser must have is_active=True.'))

        return self.create_user(first_name=first_name, last_name=last_name, password=password, **extra_fields)