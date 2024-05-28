from .models import Message
from .serializers import MessageSerializer, CreateUserSerializer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.views import View
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
import json
from .hashers import *


@method_decorator(csrf_exempt, name='dispatch')
class CreateUserView(View):
    def post(self, request, *args, **kwargs):
        # Parse JSON data from the request body
        data = json.loads(request.body)

        # Initialize serializer with data
        serializer = CreateUserSerializer(data=data)

        # Validate serializer
        if serializer.is_valid():
            # Save user
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return JsonResponse({'success': f'User created successfully:',
                                 'username': user.username,
                                 'Token': token.key}, status=status.HTTP_201_CREATED)
        else:
            # Return validation errors
            return JsonResponse({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


class UnreadMessagesForUserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Get username and password from request
        username = request.query_params.get('username')
        password = request.query_params.get('password')

        # Validate request user
        error_response, is_valid = validate_request_user(request, username, password)
        if not is_valid:
            return error_response

        if is_valid is not None:
            # User is authenticated, retrieve unread messages
            unread_messages = Message.objects.filter(receiver=request.user, is_read=False)
            serializer = MessageSerializer(unread_messages, many=True)
            if not serializer.data:
                return Response({'message': 'All messages have been read'}, status=status.HTTP_204_NO_CONTENT)
            return Response(serializer.data)
        else:
            # Authentication failed, return error response
            return Response({f'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)


class WriteMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Get username and password from request
        username = request.query_params.get('username')
        password = request.query_params.get('password')

        # Validate request user
        error_response, is_valid = validate_request_user(request, username, password)
        if not is_valid:
            return error_response

        # Check if the authenticated user is the sender
        sender_username = request.data.get('sender')
        if request.user.username != sender_username:
            return Response({'error': 'Authenticated user is not the sender.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Get receiver's username and other message data
        receiver_username = request.data.get('receiver')
        message_text = request.data.get('message')
        subject_text = request.data.get('subject')

        if not receiver_username or not message_text or not subject_text:
            return Response({'error': 'Receiver, message, and subject are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            sender = User.objects.get(username=sender_username)
            receiver = User.objects.get(username=receiver_username)
        except User.DoesNotExist:
            return Response({'error': 'Sender or receiver user does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare data for serializer
        data = {
            'sender': sender.id,
            'receiver': receiver.id,
            'message': message_text,
            'subject': subject_text
        }

        # Serialize and save the message
        serializer = MessageSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AllMessagesForUserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        username = request.query_params.get('username')
        password = request.query_params.get('password')

        # Validate request user
        error_response, is_valid = validate_request_user(request, username, password)
        if not is_valid:
            return error_response

        # Filter messages based on the current user
        messages = Message.objects.filter(sender=request.user) | Message.objects.filter(receiver=request.user)
        serializer = MessageSerializer(messages, many=True)

        # Check if there are any messages
        if not serializer.data:
            return Response({'message': 'No available messages'}, status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.data, status=status.HTTP_200_OK)


class ReadMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        username = request.query_params.get('username')
        password = request.query_params.get('password')

        # Validate request user
        error_response, is_valid = validate_request_user(request, username, password)
        if not is_valid:
            return error_response

        try:
            message = Message.objects.get(pk=pk)
        except Message.DoesNotExist:
            return Response({'message': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

        if message.receiver != request.user:
            return Response({'message': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)

        serializer = MessageSerializer(message)
        return Response(serializer.data)

    def put(self, request, pk, *args, **kwargs):
        username = request.query_params.get('username')
        password = request.query_params.get('password')

        # Validate request user
        error_response, is_valid = validate_request_user(request, username, password)
        if not is_valid:
            return error_response

        try:
            message = Message.objects.get(pk=pk)
        except Message.DoesNotExist:
            return Response({'message': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

        if message.receiver != request.user:
            return Response({'message': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)

        if message.is_read:
            return Response({'message': 'Message already been read'}, status=status.HTTP_404_NOT_FOUND)

        message.is_read = True
        message.save()
        return Response({'message': f'Message marked as read: {message.message},'
                                    f' {message.subject},'
                                    f'by: {request.user}'}, status=status.HTTP_200_OK)


class DeleteMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        username = request.query_params.get('username')
        password = request.query_params.get('password')

        # Validate request user
        error_response, is_valid = validate_request_user(request, username, password)
        if not is_valid:
            return error_response

        try:
            message = Message.objects.get(pk=pk)
        except Message.DoesNotExist:
            return Response({'message': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

        if message.sender == request.user or message.receiver == request.user:
            message.delete()
            return Response({'message': f'Message deleted successfully by {request.user}'},
                            status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'message': 'Unauthorized to delete this message'
                                        ' You are not the Sender Or the receiver '}, status=status.HTTP_403_FORBIDDEN)

