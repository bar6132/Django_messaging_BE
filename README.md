# Django Messaging Backend
Django Messaging Backend
This is a Django project that serves as a backend for a messaging application.
It provides APIs for user authentication, message creation, and message retrieval.
With security features ensure that the messaging backend provides a high level of security,


Features:

    User Authentication: Users can register, Authentication is done using tokens with robust cryptographic algorithms.

    Hashed Password Storage: User passwords are securely hashed using industry-standard cryptographic hashing algorithms before being stored in the database.
    
    Message Creation: Authenticated users can send messages to other users.
    
    Message Retrieval: Users can retrieve their messages, mark messages as read, and delete messages.

Installation:

    Clone the repository to your local machine
  
    Navigate to the project directory : cd <django-messaging-backend>
  
    Install dependencies: pip install -r requirements.txt
  
    Apply database migrations: <python manage.py migrate>
  
    Run the development server: <python manage.py runserver>
  
    The backend server should now be running at http://localhost:8000.


  Usage:

      Registration: Send a POST request to create_user/ with username and password in the request body.

  Message Creation:

    Create Message: Send a POST request to write/ with sender, receiver, message, and subject in the request body.

    use the username and password in the parms + On the Header use Authorization key with Token Value <Authorization:Token<Token_number>>

  Message Retrieval:

        use the username and password in the parms + On the Header use Authorization key with Token Value <Authorization:Token<Token_number>>

        Retrieve Messages: Send a GET request to <all/> to retrieve all messages for the authenticated user.
        
        Mark Message as Read: Send a PUT request to <mark_read/<int:pk>/> to mark a message as read.
        
        Delete Message: Send a DELETE request to <delete/<int:pk>/> to delete a message.


      
