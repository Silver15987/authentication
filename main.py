import jwt
import time 
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import socketio
from passlib.hash import bcrypt
from testtt import JWT_SECRET
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model

# call the FastAPI and socketio
sio = socketio.AsyncServer(cors_allowed_origins='*', async_mode='asgi')
app = FastAPI()
#create app and socket connection
socketio_app = socketio.ASGIApp(sio, app)

# explain what is in the database
class User(Model): 
    id = fields.IntField(pk=True)
    username = fields.CharField(25, unique=True)
    password_hash = fields.CharField(256)
    
    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)
    
async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False 
    if not user.verify_password(password):
        return False
    return user 

User_Pydantic = pydantic_model_creator(User, name='User') #everything the user will have
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True) #things user can pass as input
#if there is some read only data, we don't expect the user to pass in in so we exclude it

#OAuth2Scheme creation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
    # verify that the form data is correct
    # see if the user exist and if the password is correct

JWT_SECRET = 'MTY1NDI1MjE4Nw==' # Base64Encode the current UNIX Time
# Never share your JWT_SECRET :), based on unix time = 1654252187

async def get_current_user(token: str = Depends(oauth2_scheme)):
    # decode the token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException( status_code = 
            status.HTTP_401_UNAUTHORIZED, 
            detail='Incorrect User or Password')
    return await User_Pydantic.from_tortoise_orm(user) # the user ins't being passed directly rather it's the token


# token endpoint
@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    #print(user)

    if not user:
        return {'error': 'Invalid Credentials'}
    
    user_obj = await User_Pydantic.from_tortoise_orm(user) # convert tortoise-orm object to pydantic object
    
    #JWT_SECRET = str(int(time.time())) # Tried this method to generate random jwt secret cuase it sounded fun

    token = jwt.encode(user_obj.dict(), JWT_SECRET)
    
    return {
        'access_token' : token, 
        'token_type': 'bearer'
        }


app.mount("/", socketio_app)  # Here we mount socket app to main fastapi app

# connect event takes 2 arguments, sid is the unique session-id for a user
# assigned to a client when they connect for every event to this client, sid is going to be important for event handler
# environ is a dictionary that has all the details from the client request 
@sio.event
def connect(sid, environ):
    print("connect ", sid)


@sio.on('message')
async def chat_message(sid, data):
    print("message ", data)
    await sio.emit('response', 'hi ' + data)

@sio.event
def disconnect(sid):
    print('disconnect ', sid)


# create user endpoint
@app.post('/users', response_model=User_Pydantic) #User here is output
async def create_user(user: UserIn_Pydantic): #user here in input
    #print("Entry for temp hash is:",user.password_hash)
    temp_hash = bcrypt.hash(user.password_hash)
    
    user_obj = User(username=user.username, password_hash=temp_hash) #user will pass a username and password, and then it will be dehashed by bcrypt
    # print("In post users\nhash:{}".format(temp_hash))
    await user_obj.save() # 
    
    return await User_Pydantic.from_tortoise_orm(user_obj) # user tortoise-orm object converted into user Pydantic object
    #create the user and return their information

#
@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user

@app.get("/v2")
def read_main():
    return {"message": "Hello World"}


register_tortoise(
    app,
    db_url = 'sqlite://db.sqlite3',
    modules = {'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)