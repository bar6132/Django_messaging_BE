from django.urls import path
from .views import (WriteMessageView, AllMessagesForUserView, UnreadMessagesForUserView,
                    ReadMessageView, CreateUserView, DeleteMessageView)

urlpatterns = [
    path('write/', WriteMessageView.as_view(), name='write_message'),
    path('all/', AllMessagesForUserView.as_view(), name='all_messages'),
    path('unread/', UnreadMessagesForUserView.as_view(), name='unread_messages'),
    path('mark_read/<int:pk>/', ReadMessageView.as_view(), name='read_message'),
    path('delete/<int:pk>/', DeleteMessageView.as_view(), name='delete_message'),
    path('create_user', CreateUserView.as_view(), name='create_user'),
    path('write', WriteMessageView.as_view(), name='write_message'),
    path('all', AllMessagesForUserView.as_view(), name='all_messages'),
    path('unread', UnreadMessagesForUserView.as_view(), name='unread_messages'),
    path('mark_read/<int:pk>', ReadMessageView.as_view(), name='read_message'),
    path('delete/<int:pk>', DeleteMessageView.as_view(), name='delete_message'),
    path('create_user/', CreateUserView.as_view(), name='create_user'),
]
