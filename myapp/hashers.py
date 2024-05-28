import hashlib
from django.contrib.auth.hashers import BasePasswordHasher
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.models import User


class SHA256PasswordHasher(BasePasswordHasher):
    algorithm = 'sha256'

    def encode(self, password, salt):
        hash_value = hashlib.sha256(password.encode()).hexdigest()
        return "%s$%s" % (self.algorithm, hash_value)

    def verify(self, password, encoded):
        algorithm, hash_value = encoded.split('$', 1)
        assert algorithm == self.algorithm
        return hashlib.sha256(password.encode()).hexdigest() == hash_value

    def safe_summary(self, encoded):
        algorithm, hash_value = encoded.split('$', 1)
        assert algorithm == self.algorithm
        return {'algorithm': algorithm, 'hash': hash_value}


hasher = SHA256PasswordHasher()


def validate_request_user(request, username, password):
    print(f"Username: {username}")
    print(f"Password: {password}")

    if not request.user.is_authenticated:
        return Response({'error': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED), False

    if not username:
        return Response({'error': 'Username is required.'}, status=status.HTTP_400_BAD_REQUEST), False

    if request.user.username != username:
        return Response({'error': 'Authenticated user Token does not match the provided username.'}, status=status.HTTP_403_FORBIDDEN), False

    if not password:
        return Response({'error': 'Password is required.'}, status=status.HTTP_400_BAD_REQUEST), False

    try:
        user = User.objects.get(username=username)
        print(f"User found: {user}")
        password = hasher.encode(password=password, salt=None)

        # Authenticate the user with plain text password
        user = authenticate(request, username=username, password=password)
        print(f"Authenticated user: {user}")  # Log the authenticated user

        if user is None:
            print("Authentication failed")
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED), False

    except User.DoesNotExist:
        print("User does not exist")
        return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED), False

    return None, True