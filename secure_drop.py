import func
import sys,json
import threading
import binascii
import hashlib

with open('file.txt', 'r') as file_obj :
    contents=file_obj.read()
    a=len(contents)
    login=0
    not_sending=[1]
    response=['n']
    user=0
    if a==0 :
        func.register(user);
        sys.exit("Exiting SecureDrop.")
    else:
        print("Enter email address: ")
        
        user_email=input()
        print("enter password")
        user_password=input()
        data_1 = json.load(open("file.txt"))
        saved_id=data_1['email']
        hashed_password=data_1['password']
        salt = hashed_password[:64]
        hashed_password = hashed_password[64:]
        salt=salt.encode('ascii')
        user_pwd_hash = hashlib.pbkdf2_hmac('sha512', user_password.encode('utf-8'), salt, 100000)
        user_pwd_hash = binascii.hexlify(user_pwd_hash)
        user_pwd_hash=user_pwd_hash.decode('ascii')
        #print(user_pwd_hash)
        if saved_id==user_email and hashed_password == user_pwd_hash:
            login=1
        if login==1:
            thread=threading.Thread(target=func.server, args=(not_sending,response,))
            thread.daemon=True
            thread.start()
            with open('file.txt','r') as file_obj:
                jsondata=file_obj.read()
            data=json.loads(jsondata)
            while 1:
                while not_sending[0]:
                    choice=input("Type help For Commands.\n")
                    if choice=="help":
                        print("add  -> Add a new contact\nlist -> List all online contacts\nsend -> Transfer file to contact\nexit -> Exit SecureDrop")
                    elif choice=="add":
                        data_added=func.add(data);
                        json_data=json.dumps(data_added)
                        with open('file.txt','w')as file_obj :
                            file_obj.write(json_data)
                        print("Contact Added.")
                    elif choice=="exit":
                        sys.exit("Exiting SecureDrop.")
                    elif choice=="list":
                        print("The following contacts are online:")
                        func.client_list()
                    elif choice=="send":
                        target=input("Enter a contact to send:")
                        filename=input("Enter the file name:")
                        func.client_send(target,filename)
                    elif choice=="y":
                        response[0]='y'
                    else:
                        pass
        else:
            print("login failed.")
            sys.Exiting()
            
            
            
            
                
