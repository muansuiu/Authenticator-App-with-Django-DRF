from django.core.validators import MinLengthValidator, EmailValidator, RegexValidator

class FieldValidators:
    email_validator = EmailValidator()
    password_validator = MinLengthValidator(8, message='Password must be at least 8 characters.')

    mobile_validator = RegexValidator(
            regex=r'^880\d{10}$',
            message='Mobile number should start with 880 and have 13 characters.',
            code='invalid_mobile'
        )

    name_validator = RegexValidator(
            regex=r'^[A-Za-z ]+$',
            message='Only letters are allowed',
            code='invalid_name'
        )