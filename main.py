import jwt
import time 
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model

app = FastAPI()

# explain what is in the database
class User(Model): 
    id = fields.IntField(pk=True)
    username = fields.CharField(25, unique=True)
    password_hash = fields.CharField(256)

    @classmethod
    async def getUser(cls, username):
        return cls.get(username = username)
    
    def verifyPassword(self, password):
        print("In function verifyPassword")
        print("password: ",password)
        print("password hash: ", self.password_hash)
        return bcrypt.verify(password, self.password_hash)
    
User_Pydantic =  pydantic_model_creator(User, name='User') #everything the user will have
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True) #things user can pass as input
#if there is some read only data, we don't expect the user to pass in in so we exclude it

#OAuth2Scheme creation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
    # verify that the form data is correct
    # see if the user exist and if the password is correct
async def authenticate_user(username: str, password: str):
    user = await User.get(username = username)
    #print("in authenticate_user:\n user:{}\npassword:{}\nverifyPassword:{}".format(user.username, password,user.verifyPassword))
    if not user:
        print("User not???")
        return False
    if user.verifyPassword(password):
        print("not verified???")
        return False
    return user

# token endpoint
@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    print(user)
    if not user:
        return {'error': 'Invalid Credentials'}
    
    user_obj = await User_Pydantic.from_tortoise_orm(user) # convert tortoise-orm object to pydantic object
    token = jwt.encode(user_obj.dict(), JWT_SECRET = int(time.time()))
    return {
        'access_token' : token, 
        'token_type': 'bearer'
        }

@app.post('/users', response_model=User_Pydantic) #User here is output
async def create_user(user: UserIn_Pydantic): #user here in input
    print("Entry for temp hash is:",user.password_hash)
    temp_hash = bcrypt.hash(user.password_hash)
    user_obj = User(username=user.username, password_hash=temp_hash) #user will pass a username and password, and then it will be dehashed by bcrypt
    print("In post users\nhash:{}".format(temp_hash))
    await user_obj.save() # 
    return await User_Pydantic.from_tortoise_orm(user_obj) # user tortoise-orm object converted into user Pydantic object
    #create the user and return their information


register_tortoise(
    app,
    db_url = 'sqlite://db.sqlite3',
    modules = {'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)