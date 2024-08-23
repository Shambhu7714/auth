API forget_password/

Problem Solve:- Forgot Reset Password

API Nmae :- "forget_password/" FOR Accept POST Request Only API URLS:- "path("forget_password/", views.ForgotResetPassword.as_view(), name="forgot_reset_password")," Runsever Urls:- http://127.0.0.1:8000/userprofile/forget_password/ API Views.py:- Function Name where Define API forget_password function name is "ForgotResetPassword" API Models.py:- This API Needs the TABLE Name is- User, Email_logs and EmailTemplates

Import necessary liberay import re from django.contrib.auth.hashers import check_password from django.contrib.auth.password_validation import validate_password from django.core.exceptions import ValidationError from django.http import JsonResponse from django.utils.decorators import method_decorator from django.views.decorators.csrf import csrf_exempt from datetime import datetime from .models import User, EmailsLogs,

Description:

This API handles password resets for users of a Django application.
It enables users to request an OTP (One-Time Password) via email and then reset their password using the OTP.
Key Features:

Secure password resets using OTP verification
Enforces password complexity requirements
Prevents password reuse
if OTP is Expired to 10 minutes
if OTP is alredy used then we cannot user next time
if user is enter 3 times inviled OTP return an error JSON response Account locked. Contact admin.
Functionality:

POST Method: This endpoint accepts POST requests to reset the password.
If no OTP is provided, the API sends an OTP to the user's email address.
If an OTP is provided, the API verifies it and resets the user's password.
Request Parameters

email: User's email address.
otp_entered: OTP (One-Time Password) entered by the user.
new_password: New password to set.
confirm_password: Confirmation of the new password.
Response

If no OTP is provided:

If successful, returns a JSON response containing the OTP.
If unsuccessful, returns an error JSON response with details.
If an OTP is provided:

If successful, resets the user's password and returns a success message.
If unsuccessful, returns an error JSON response with details.
If a OTP is Expired, return an error JSON response Expired OTP.
If a OTP is alredy used, return an error JSON response OTP is alredy used.
if user is enter 3 times inviled OTP return an error JSON response Account locked. Contact admin.
Additional Details

Password Complexity Requirements:

Password must be between 6 and 25 characters.
Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character.
Other Validation:

Email address validation.
OTP format and validity check.
Matching of new password and confirmation password.
Check if the new password is the same as the old password.
Validation against Django's password validators.
validation OTP enter times
User Feedback:

Error messages are returned in case of validation failures or errors.
Success message is returned upon successful password reset.
Dependencies:

Django: Used for building the API endpoint.
Django Rest Framework: Used for handling HTTP requests and responses.
Python Regular Expressions (re): Used for defining password complexity requirements.
Django Password Validators: Used for validating new passwords against Django's password validators.
Usage:

To use this API endpoint, send a POST request with the required parameters (email, otp_entered, new_password, confirm_password) to the endpoint URL.
Example usage with cURL:

curl -X POST
-d "email=Shambhu@botshyeyasi"
-d "otp_entered=123456"
-d "new_password=shamBhu123@"
-d "confirm_password=shamBhu123@"
http://127.0.0.1:8000/userprofile/forget_password/

Notes

Ensure proper error handling and validation on the client-side when using this API endpoint.
Implement rate limiting and other security measures to prevent misuse or abuse of the endpoint.
Review and customize password complexity requirements and other validation rules as per your application's requirements.
#_________________________________________________________ RESEND OTP____________________________________________________________#

API Resend_OTP Problem Solve:- Resend OTP

API Nmae :- "Resend_OTP/" FOR Accept POST Request Only API URLS:- "path('Resend_OTP/', views.Resend_OTP.as_view(), name='Resend_OTP')," Runsever Urls:- http://127.0.0.1:8000/userprofile/Resend_OTP/ API Views.py:- Function Name where Define API Resend_OTP function name is "Resend_OTP(APIView):" API Models.py:- This API Needs the TABLE Name is- User, Email_logs and EmailTemplates

Description: This code provides functionality to resend OTP (One Time Password) to users via email. It's implemented in Django and uses a combination of views and models to achieve this.

Key Features:

Resend OTP via Email.
Resend OTP only 5 times
Functionality:

Generate OTP: Generates a random OTP of specified length.
Resend OTP: Resends OTP to the user's email address
OTP Expiry: Sets the expiry time for OTPs to ensure security.
Forget Password Attempts: Tracks the number of forget password attempts and blocks the account after exceeding the limit.
Response:

If the OTP is successfully resent, the response will contain a success message.
If the user is not found in the database, it will return a message indicating that the user was not found.
If the forget password attempts have exceeded the limit, it will return a message indicating that the account has been blocked due to exceeding the attempts limit.
Success Response:

{ "message": "OTP Resend successfully"}

User Not Found Response { "message": "User not found"}

Exceeded Attempts Response { "message": "Forget password attempts exceeded. Your account has been blocked."}

Usage To use the Resend OTP functionality, follow these steps:

Send a POST request to the appropriate endpoint with the user's email

The system will generate a new OTP and send it to the user's email address

Example usage with cURL:

curl -X POST
-d "email=Shambhu@botshyeyasi"
http://127.0.0.1:8000/userprofile/Resend_OTP/

Request Parameters:

email: User's email address.
Dependencies:

pip freeze > requirements.txt
Django==3.2.12
djangorestframework==3.12.4
pip install -r requirements.txt
###Generate OTP___#######

API Generate_OTP/ Problem Solve:- OTP Generate

API Nmae :- "Generate_OTP/" FOR Accept POST Request Only API URLS:-path('Generate_OTP/', views.SendAndVerifyOTP.as_view(), name='SendAndVerifyOTP'), Runsever Urls:- http://127.0.0.1:8000/userprofile/Generate_OTP/ API Views.py:- Function Name where Define API Generate function name is "SendAndVerifyOTP(APIView):" API Models.py:- This API Needs the TABLE Name is- User, Email_logs,

Description: This code provides functionality to generate OTP (One Time Password) via email. It includes an API endpoint to handle OTP generation and verification.

Key Features:

Generate OTP via Email.
Functionality:

Generate OTP: Generates a random OTP of specified length.
Send OTP: Sends the generated OTP to the user's email address.
Response:

OTP Generate successfully
Success Response:

{ "message": "OTP Generate successfully"}
Usage To use the Resend OTP functionality, follow these steps:

Send a POST request to the appropriate endpoint with the user's email

The system will generate a new OTP.

Example usage with cURL:

curl -X POST
-d "email=Shambhu@botshyeyasi"
http://127.0.0.1:8000/userprofile/Generate_OTP/

Request Parameters:

email: User's email address.
Dependencies:

pip freeze > requirements.txt
Django==3.2.12
djangorestframework==3.12.4
pip install -r requirements.txt
#API Email-Validation_###### API Email-Validation Problem Solve:- Email-Validation Via OTP

API Nmae :- Email-Validation/ FOR Accept POST Request Only API URLS:- path("Email-Validation/", views.ValidateEmail.as_view(), name="ValidateEmail"), Runsever Urls:- http://127.0.0.1:8000/userprofile/Email-Validation/ API Views.py:- Function Name where Define API account_locked function name is "account_locked(APIView):" API Models.py:- This API Needs the TABLE Name is- User, EmailsLogs

Description: This functionality to validate an email address using a One Time Password (OTP). It checks if the OTP entered by the user matches the one stored in the database for the given email.

Key Features:

Validate email using OTP .
Validate User Validate or not via Email OTP.
Functionality:

Validate Email: Validates an email address using a One Time Password (OTP) stored in the database.
Check OTP: Compares the OTP entered by the user with the one stored in the database for the given email.
Handle Validation: Returns success message if the OTP matches the one stored in the database; otherwise, returns an error message.
Response:

If the OTP entered by the user matches the one stored in the database, the response will contain a success message indicating that the email has been validated successfully.
If the OTP entered by the user does not match the one stored in the database, the response will contain an error message indicating that the OTP is invalid. JSON Response:
Success Response (HTTP 200 OK) { "message": "Email validated successfully" }
Invalid OTP Response (HTTP 400 Bad Request): { "error": "Invalid OTP" }
Usage:

Send a POST request to the appropriate endpoint with the user's email and OTP:
POST /validate-email/ { "email": "Shambhu@botshreyasi", "otp": "123456" }
Request Parameters:

email: User's email address.
OTP: User's provided OTP.
Dependencies:

pip freeze > requirements.txt
Django==3.2.12
djangorestframework==3.12.4
pip install -r requirements.txt
#_API account_locked###########

API account_locked Problem Solve:- account_locked

API Nmae :- "account_locked/" FOR Accept POST Request Only API URLS:- "path('account_locked/', views.Resend_OTP.as_view(), name='account_locked')," Runsever Urls:- http://127.0.0.1:8000/userprofile/account_locked/ API Views.py:- Function Name where Define API account_locked function name is "account_locked(APIView):" API Models.py:- This API Needs the TABLE Name is- User

Description: This code provides functionality to handle account lockout for users after a certain number of failed login attempts. It is implemented using Django and Django REST Framework.

Key Features:

login Requried .
Password Requried.
both Match login success.
if user Attempt 3 times invield then Account locked
Functionality:

Check Login Attempts: Checks the number of login attempts made by the user and locks the account if the limit is exceeded.
Handle Invalid Credentials: Handles cases of invalid credentials during login attempts and updates the login attempts count.
Lock Account: Locks the user account if the number of failed login attempts exceeds the threshold.
Response:

If the login attempt is successful, the response will contain a message indicating the successful login.
If the provided credentials are invalid, the response will contain an error message indicating the number of remaining login attempts.
If the user's account is locked due to exceeding the maximum number of login attempts, the response will contain an error message indicating that the account is locked.
If the user with the provided email does not exist, the response will contain an error message indicating that the user does not exist. Success Response: POST /account-locked/
{ "message": "Login successful" }
{ "error": "Invalid credentials. 2 attempts remaining." }
{ "error": "Invalid credentials. Account locked. Contact admin." }
{ "error": "User does not exist" }
Usage:

To use the Resend OTP functionality, follow these steps:

Send a POST request to the appropriate endpoint with the user's email

Login Security perpose.

User Needs there Password

Example usage with cURL:

curl -X POST
-d "email=Shambhu@botshyeyasi"
-d "Password=Shambh123@" http://127.0.0.1:8000/userprofile/account_locked/

Request Parameters:

email: User's email address.
Password: User's Password.
Dependencies:

pip freeze > requirements.txt
Django==3.2.12
djangorestframework==3.12.4
pip install -r requirements.txt
#####USER Unblock API###############

API account_locked Problem Solve:- User_Unblock

API Nmae :- "User_unblock/" FOR Accept POST Request Only API URLS:- path('User_unblock/', views.UnblockUser.as_view(), name='UnblockUser'), Runsever Urls:- http://127.0.0.1:8000/userprofile/User_Unblock/ API Views.py:- Function Name where Define API User_Unblock function name is "class UnblockUser:" API Models.py:- This API Needs the TABLE Name is- User

Description: The UnblockUser API endpoint is designed to unblock users who have been previously blocked due to exceeding the maximum number of forget password attempts within a 24-hour period.

Functionalities:

Unblocks a User based on provided email address.
Handles cases where the provided email doesn't match an existing User.
Handles cases where the User is not currently blocked.
Ensures 24 hours have passed since the last forget password attempt before unblocking.
Supported HTTP Method:

POST Request Data:
email: Email address of the User to unblock.
Response:

On successful unblock:
Status code: 200 OK
Response message: "User unblocked successfully"
On error: Status code: 400 Bad Request * Response message: Error message explaining the issue (e.g., "User not found", "User is not blocked", "24 hours have not passed since last attempt")
Example Request: POST /api/unblock/ HTTP/1.1 Content-Type: application/json { "email": "example@example.com" }

Notes: This API relies on the following User model fields: * forget_password_attempts: An integer counter for forget password attempts. * last_login: A timestamp of the User's last login. The logic assumes a threshold of 5 forget password attempts before blocking the User. You might need to adjust this based on your specific requirements.

###User Details Update API___####################

API User_update/

Problem Solve:- User Details Update

API Nmae :- "Application_update/" FOR Accept POST Request and GET Request API URLS:- path('User_update/int:user_id/', views.UpdateUser.as_view(), name=''Update_User_Details''), Runsever Urls:-http://192.168.4.14:8001/application/Application_update/1/ (application_id=1) API Views.py:- Function Name where Define API function name is "UpdateUser" API Models.py:- This API Needs the TABLE Name is- User

Description Your Application Name is a Django application designed for managing application details. It provides APIs to retrieve and update user information such as address, mobile number, billing details, etc.

Functionality:

Provides functionalities to retrieve and update user details.
GET Request retrieve details
PUT Request update details
GET Method (get):

Retrieves details of a specific User based on the provided user_id. Request Parameters:

user_id: (Integer) Unique identifier of the user.

Response: On success: JSON object with a success message. On failure: JSON object with error message and status code: * Status code: 400 (Bad Request) - Missing required fields in request body (commented out in the provided code). * Status code: 404 (Not Found) - User with provided ID does not exist. * Status code: 400 (Bad Request) - Username or email mismatch (commented out in the provided code).

PUT Method (put): Updates details of a specific application based on the provided application_id.

Request Parameters: None in the URL path. Data is sent in the request body.

Request Body (JSON):

(Optional fields can be omitted)
first_name: (String) Updated first name.
last_name: (String) Updated last name.
username: (String) Updated username.
email: (String) Updated email address.
phone: (String) Updated phone number.
gender: (String) Updated gender.
profile_pic: (String) Updated profile picture URL.
dob: (String) Updated date of birth (format needs clarification based on model field).
short_name: (String) Updated short name. Response:
On success: JSON object with a success message.
On failure: JSON object with error message and status code:
Status code: 400 (Bad Request) - Required fields (user_id, email, name) are missing in request body.
Status code: 404 (Not Found) - User with provided ID does not exist.
Notes:

The email and name fields are not mentioned in the provided code but might be required based on comments. Update the document accordingly if those fields are indeed required.
##Application and User Details Update__###########

Problem Solve:- Forgot Reset Password

API Nmae :- "User&App/" FOR Accept POST Request Only API URLS:- path('User&App/', views.UpdateAPIView.as_view(), name='Update_User_and_Application_Details'), Runsever Urls:- http://127.0.0.1:8000/userprofile/User&App/ API Views.py:- Function Name where Define API User&App/ function name is "UpdateAPIView" API Models.py:- This API Needs the TABLE Name is- User,Application

Description: The UpdateAPIView is a Django REST Framework view that handles updates for both users and applications. It allows updating user information and application details based on the provided user_id or application_id respectively.

Functionalities:

Updates User details based on provided user_id.
Updates Application details based on provided application_id.
Handles cases where neither user_id nor application_id is provided.
Handles cases where the provided ID doesn't match an existing User or Application. Supported HTTP Method: PUT Request Data:
You can update any of the following fields for a User:
first_name
last_name
username
email
phone
gender
profile_pic
dob
short_name *You can update any of the following fields for an Application:
application_address
is_ats
application_mobileno
license_start_date
license_end_date
website
application_pan_no
application_gst_no
default_status_id
default_referrer_id
secret_key
state_name
logo_url
application_about
billing_name
Response:

On successful update:
Status code: 200 OK
Response message: "User details updated successfully" (for User update) or "Application details updated successfully" (for Application update)
Optional (commented out): Detailed information about the updated User or Application.
On error:
Status code: 400 Bad Request (for missing user_id or application_id) Status code: 404 Not Found (for non-existent User or Application ID)
Response message: Error message explaining the issue (e.g., "User with provided ID does not exist")
Example: PUT /api/update/ HTTP/1.1 Content-Type: application/json

{ "user_id": 123, "first_name": "shambhu", "last_name": "kumar", "email": "shambhu.k@botshreyasi" } PUT /api/update/ HTTP/1.1 Content-Type: application/json

{ "application_id": 456, "application_address": "d, City", "website": "https://example.com" }

Notes: Currently, comments within the code indicate optional sections for returning detailed User or Application information in the response. You can uncomment these sections if needed.

Contributing Contributions are welcome! If you encounter any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

License This project is licensed under the MIT License. See the LICENSE file for details.

Here is the updated README file, incorporating the LogoutView functionality as well:

Django Authentication API
Overview
This Django application provides endpoints for user authentication, tracking login activities, and handling user logout. It includes:

Login Endpoint: Authenticates users and generates JWT tokens.
User Login Activity Endpoint: Retrieves user details and their login activities.
Logout Endpoint: Logs out the user by clearing the session and updating the activity log.
Requirements
Django
Django REST Framework
djangorestframework-simplejwt for JWT authentication
pytz for timezone handling
Endpoints
1. LoginView
Endpoint: /api/login/
Method: POST

Description: Authenticates a user and generates JWT tokens upon successful login.

Request Body:

{
    "email": "user@example.com",
    "password": "password123"
}
Response (Success):

{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
Response (Error):

{
    "detail": "Invalid credentials"
}
Functionality:

Authenticate: Checks user credentials.
Generate Tokens: Creates JWT access and refresh tokens.
Track Login: Logs the login attempt with details such as email, IP address, and user agent.
Update Last Login: Updates the user's last login timestamp.
2. UserLoginActivityView
Endpoint: /api/user-activity/
Method: GET

Description: Retrieves user details along with their login activities.

Query Parameters:

email (required): The email address of the user whose details are being requested.
Response (Success):

{
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "last_login": "2024-08-21T15:00:00Z",
    "logout": "2024-08-21T17:00:00Z",
    "estimated_logout": "2024-08-21T16:00:00Z",
    "is_active": true,
    "activity_logs": [
        {
            "id": 1,
            "email": "user@example.com",
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "created_at": "2024-08-21T14:00:00Z",
            "logout_time": null,
            "attempt_name": "login_success"
        }
    ]
}
Response (Error):

{
    "error": "User not found."
}
Functionality:

Retrieve User Info: Fetches user details such as email, last login, and logout time.
Activity Logs: Includes a list of login activities with details such as IP address, user agent, and timestamps.
3. LogoutView
Endpoint: /api/logout/
Method: POST

Description: Logs out the user by clearing the session and updating the logout time in the activity log.

Request Body: None required.

Response (Success):

{
    "detail": "Logout successful."
}
Response (Error):

{
    "error": "User is not authenticated."
}
Functionality:

Update User Logout Time: Records the logout time in the User model.
Update Activity Log: Updates the existing activity log with the logout time or creates a new log entry if one does not exist.
Clear Session: Logs out the user by clearing all session data.
Installation
Clone the Repository:

git clone https://github.com/your-repo.git
cd your-repo
Install Dependencies:

pip install -r requirements.txt
Apply Migrations:

python manage.py migrate
Run the Development Server:

python manage.py runserver
Configuration
Ensure that you have configured the JWT settings in your Django settings file. For example:


## Testing

You can test the endpoints using tools like Postman or `curl`. Ensure that you send the correct request parameters and headers.

---


