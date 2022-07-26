import json
import getpass,binascii
import hashlib,os
import netifaces,nmap
import socket
import sys
import threading
from cmd import Cmd
#ip scan
def get_gateways():
    return netifaces.gateways()['default'][netifaces.AF_INET][0]

def get_ip_lists(gateway):
    ip_lists = []
    for i in range(1, 256):
        ip_lists.append('{}{}'.format(gateway[:-1], i))
    return ip_lists

def search(ip=None):
    ip=get_gateways()
    ip_lists=get_ip_lists(ip)
    nmScan,temp_ip_lists,hosts = nmap.PortScanner(),[],ip[:-1]+'0/24'
    ret = nmScan.scan(hosts=hosts, arguments='-sP')
    for ip in ip_lists:
        if ip not in ret['scan']:
            temp_ip_lists.append(ip)
        else:
            pass
    for ip in temp_ip_lists:
        ip_lists.remove(ip)
    return ip_lists


    
    
#new user
def register(user):
    while user==0 :
        print("No users are registered with this client.")
        b=input("Do you want to register a new user (y/n)?")
        if b=="y" :
            print("\nEnter Full Name: ")
            name=input()
            print("Enter Email Address: ")
            email=input()
            print("Enter Password: ")
            password=getpass.getpass()
            print("Re-enter Password: ")
            password_check=getpass.getpass()
            if password==password_check :
                salt=os.urandom(60)
                salt = hashlib.sha256(salt)
                salt=salt.hexdigest().encode('ascii')
                hashed_password = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
                hashed_password = binascii.hexlify(hashed_password)
                hashed_password= (salt + hashed_password).decode('ascii')







                #salt = os.urandom(32).hex()
                #hashx=hashlib.sha512()
                #hashx.update(salt.encode('utf-8'))
                #hashx.update(password.encode('utf-8'))

                
                #hash=hashlib.sha512()
                #hash.update(('%s%s'%(salt,password)).encode('utf-8'))
                #hashed_password = hashx.hexdigest()
                data={'name': name, 'email': email, 'password':hashed_password}
                json_data=json.dumps(data)
                with open('file.txt','a')as file_obj :
                    file_obj.write(json_data)
                print("Passwords Match.\nUser Registered.")
                user=1
        else:
            print("There is no user so you might want to register a new one")
    return 

class drop_shell(Cmd):
    #prompt = 'secure_shell> '
    intro = "Welcome to Secure Drop! Type help for commands:"
    def do_exit(self,args):
        sys.exit("Exiting SecureDrop.")
    def do_help(self,args):
        print("add  -> Add a new contact\nlist -> List all online contacts\nsend -> Transfer file to contact\nexit -> Exit SecureDrop")
    def do_add(self,args):
        with open('file.txt','r') as file_obj:
            jsondata=file_obj.read()
        data=json.loads(jsondata)
    
        data_added=add(data)
        json_data=json.dumps(data_added)
        with open('file.txt','w')as file_obj :
            file_obj.write(json_data)
        print("Contact Added.")
    def do_list(self,args):
        print("The following contacts are online:")
        client_list()
    def do_send(self,args):
        target=input("Enter a contact to send:")
        filename=input("Enter the file name:")
        client_send(target,filename)
#add contact
def add(data):
    print("Enter Full Name:")
    name=input()
    print("Enter Email Address:")
    email=input()
    data[name]=email
    return data


#server part
def server(not_sending,response):
    serversocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host=''
    port=23333
    serversocket.bind((host, port))
    serversocket.listen(5)
    notinlist='I dont have you in my contact list'
    while True:
        clientsocket,addr = serversocket.accept()
        schoice=clientsocket.recv(4)
        choice=schoice.decode('utf-8')
        if choice=="list":
            with open('file.txt','r') as file_obj:
                jsondata=file_obj.read()
            data=json.loads(jsondata)
            snamereq = clientsocket.recv(4096)
            namereq=snamereq.decode('utf-8')
            if namereq in data.keys():
                clientsocket.send(data['name'].encode('utf-8'))
            else:
                clientsocket.send(notinlist.encode('utf-8'))
        elif choice=="send":
            with open('file.txt','r') as file_obj:
                jsondata=file_obj.read()
            data=json.loads(jsondata)
            snamereq = clientsocket.recv(4096)
            namereq=snamereq.decode('utf-8')
            if namereq in data.keys():
                clientsocket.send(data['name'].encode('utf-8'))
            else:
                clientsocket.send(notinlist.encode('utf-8'))
        elif choice=="requ":
            with open('file.txt','r') as file_obj:
                jsondata=file_obj.read()
            data=json.loads(jsondata)
            snamereq = clientsocket.recv(4096)
            namereq=snamereq.decode('utf-8')
            print("Contact' "+repr(namereq)+"<"+repr(data[namereq])+">'is sending a file. Accept (y/n)?",end='')
            not_sending[0]=0
            input("Enter anything to recieve file:")
            if response[0]=='y':
                clientsocket.send(response[0].encode('utf-8'))
                sfile_size = clientsocket.recv(1024)
                file_size= int(sfile_size.decode('utf-8'))
                clientsocket.send(b'111')
                sfilename=clientsocket.recv(4068)
                filename=sfilename.decode('utf-8')
                clientsocket.send(b'111')
                new_file_size = file_size
                f = open(filename, 'wb')
                m = hashlib.sha512()
                while new_file_size > 0:
                    data = clientsocket.recv(4096)
                    new_file_size -= len(data)
                    m.update(data)
                    f.write(data)
                else:
                    new_file_sha512 = m.hexdigest()
                    f.close()
                sserver_file_sha512 = clientsocket.recv(4096)
                server_file_sha512 = sserver_file_sha512.decode()
                if new_file_sha512==server_file_sha512:
                    clientsocket.send(b'true')
                    print("File has been successfully recieved.")
                    not_sending[0]=1
                    response[0]=='n'
                else:
                    clientsocket.send(b'false')
                    not_sending[0]=1
                    response[0]=='n'
            else:
                clientsocket.send(response[0].encode('utf-8'))
                not_sending[0]=1
        else:
            pass
        clientsocket.close()
    return

#client try to list
def client_list():
    ip_list=search()
    with open('file.txt','r') as file_obj:
        jsondata=file_obj.read()
    data=json.loads(jsondata)
    choice="list"
    for ip in ip_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ret=s.connect_ex((ip,23333))
        if ret == 0:
            s.send(choice.encode('utf-8'))
            s.send(data['name'].encode('utf-8'))
            snameback=s.recv(4096)
            nameback=snameback.decode('utf-8')
            s.close()
            if nameback in data.keys():
                print("* "+repr(nameback)+"<"+repr(data[nameback])+">")
            else:
                pass
        else:
            pass
    return

#client try to send
def client_send(email,filename):
    ip_list=search()
    with open('file.txt','r') as file_obj:
        jsondata=file_obj.read()
    data=json.loads(jsondata)
    contactlist={}
    choice="send"
    for ip in ip_list:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ret=s.connect_ex((ip,23333))
        if ret == 0:
            s.send(choice.encode('utf-8'))
            s.send(data['name'].encode('utf-8'))
            snameback=s.recv(4096)
            nameback=snameback.decode('utf-8')
            s.close()
            if nameback in data.keys():
                contactlist[data[nameback]]=ip
            else:
                pass
        else:
            pass
    if email in contactlist.keys():
        choice="requ"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((contactlist[email],23333))
        s.send(choice.encode('utf-8'))
        s.send(data['name'].encode('utf-8'))
        sresponse=s.recv(4096)
        response=sresponse.decode('utf-8')
        if os.path.isfile(filename):
            if response=='y':
                print("Contact has accepted the transfer request.")
                f = open(filename, 'rb')
                m = hashlib.sha512()
                file_size = os.stat(filename).st_size
                s.send(str(file_size).encode('utf-8'))
                s.recv(4096)
                #filename=os.path.split(filename)[1]
                s.send(filename.encode('utf-8'))
                s.recv(4096)
                for line in f:
                    m.update(line)
                    s.send(line)
                f.close()
                s.send(m.hexdigest().encode())
                result=s.recv(4096)
                if result == b'true':
                    print("File has been successfully transferred.")
                else:
                    print("File transfer failed.")
            else:
                print("repuest declined.")
        else:
            print("This is not a legal address")
    else:
        print("He/She is not online or not in your contact list")
    return

