from rest_framework.exceptions import AuthenticationFailed, APIException
from django.contrib.auth.hashers import check_password, make_password
from accounts.models import User
from companies.models import Enterprise, Employee

class Authentication():

    def signin(self, email=None, password=None):
        exception_auth = AuthenticationFailed("E-mail e/ou senha incorreto(s).")

        user_exists = User.objects.filter(email=email).exists()
        if not user_exists:
            raise exception_auth
        
        user = User.objects.filter(email=email).first()
        if not check_password(password=password, encoded=user.password):
            raise exception_auth

        return user
    
    def signup(self, name, email, password, type_account='owner', company_id=False):
        data_exception = APIException("Alguns dos dados (nome, email ou senha) está inválido.")
        email_unique_exception = APIException("Esse e-mail já está sendo utilizado na plataforma.")
        employee_without_company = APIException("O id da empresa não deve ser nulo.")
        
        if not name or name == '' or not email or email == '' or not password or password == '':
            raise data_exception
        
        if type_account == 'employee' and not company_id:
            raise employee_without_company
        
        #Verifica se o email já não está sendo usado
        user = User.objects.filter(email=email)
        if user.exists():
            raise email_unique_exception
        
        password_hashed = make_password(password)

        created_user = User.objects.create(
            name=name, email=email, 
            password=password_hashed, 
            is_owner=0 if type_account == "employee" else 1
        )

        if type_account == 'owner':
            created_enterprise = Enterprise.objects.create(
                name="Nome da empresa",
                user_id=created_user.id
            )
        
        if type_account == "employee":
            Employee.objects.create(
                enterprise_id=company_id or created_enterprise.id, 
                user_id=created_user.id
            )
        
        return created_user