"""
** PASSager - Password Manager **
A Password Manager that works offline! Fully open source and free to use! 
You no longer need to remember passwords! And all your passwords are in safe hands!

- If you find a error or have a complaint, please email us at -
  crisissoftwaresolutions@gmail.com
- Please do read the README.md file before running the application!

![ATTENTION]!
Use the application at your own risk. Though the security measures used are good enough to protect
your passwords, we cannot ensure that they are safe in uncontrolled conditions (such as a ransomeware attack,
or if your device gets stolen). We are not responsible for any loss that you endure.

- By: Lonely Coffee (The CRISIS Team)
- Copyright © 2023, Crisis Software Solutions (Privacy and Security), All Rights Reserved
"""
import customtkinter
from tkinter import *
import tkinter as tk
import json
from PIL import Image
import os
from passgen import passgen
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

def kdfInt(saltI):
    kdfI = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=saltI,
        iterations=480000, #Recomended
        )
    return kdfI

def kdf_derive_key(kdfinstance, txt):
    return base64.urlsafe_b64encode(kdfinstance.derive(txt))

class pass_manager:

    def __init__(self):
        self.key = None
        self.pass_file = None
        self.pass_dict = {}

    def load_key(self, password, kdfinst):
        self.key = kdf_derive_key(kdfinstance=kdfinst, txt=password.encode())
    
    def load_pwd_file(self, path):
        self.pass_file = path

        with open(path, 'r') as f:
            for line in f:
                site, encrypted = line.split(":")
                self.pass_dict[site] = Fernet(self.key).decrypt(encrypted.encode()).decode()
    
    def add_pwd(self, site, password):
        self.pass_dict[site] = password

        if self.pass_file is not None:
            with open(self.pass_file, 'a+') as f:
                        encrypted = Fernet(self.key).encrypt(password.encode())
                        f.write(site + ":" + encrypted.decode() + "\n")

    def get_pwd(self, site):
        return self.pass_dict[site]

    def encrypt_2(self, message):
        return Fernet(self.key).encrypt(message.encode()).decode()

    def decrypt_2(self, message):
        return Fernet(self.key).decrypt(message.encode()).decode()
    
    def exitingFunc(self):
        self.key = None
        self.pass_file = None
        self.pass_dict = {}

PM = pass_manager()

with open('settings.json') as config_file:
    data = json.load(config_file)

if data["theme"] == "dark":
    customtkinter.set_appearance_mode("dark")
elif data["theme"] == "light":
    customtkinter.set_appearance_mode("light")
else:
    customtkinter.set_appearance_mode("System")

if data["template"] == "green":
    customtkinter.set_default_color_theme("green")
else:
    customtkinter.set_default_color_theme("blue")

root = customtkinter.CTk()
root.geometry("795x480")
root.title("PASSager - Password Manager (v 1.0.0)")

def loginScreen():
    root.title("PASSager - Authentication")
    lframe = customtkinter.CTkFrame(master=root)
    lframe.pack(padx=20, pady=20, fill="both", expand=True)

    def pass_check():
        mP = masterpassword.get()
        #mpL = hashlib.sha256(mP.encode())
        #hexmpL = mpL.hexdigest()
        #with open("assets/files/key.hash", "r") as g:
            #Rmp = g.read()
        #if hexmpL == Rmp:
            #kdf = kdfInt(salt)
            #key = kdf_derive_key(kdf, mP.encode())
            #lframe.pack_forget()
            #managerScreen()
        #else:
            #errLbl3.pack(before=masterpassent)
        with open("salt.key", "rb") as f:
            salt = f.read()
        kdf = kdfInt(salt)
        try:
            PM.load_key(kdfinst=kdf, password=mP)
            PM.load_pwd_file(path="assets/files/passwords.pass")
            lframe.pack_forget()
            managerScreen()
        except:
            errLbl3.pack(before=masterpassent)

    image1 = customtkinter.CTkImage(Image.open("assets/images/passStart.png"), size=(470, 150))
    img = customtkinter.CTkLabel(master=lframe, image=image1, text="")
    img.pack(padx=30, pady = 20)

    authlbl = customtkinter.CTkLabel(master=lframe, text="Authentication", font=("Helvetica Light", 20))
    authlbl.pack(padx=10, pady=12)

    passentr = customtkinter.CTkLabel(master=lframe, text="Enter you Master Password", font=("Helvetica Light", 15))
    passentr.pack(padx=5, pady=2)

    errLbl3 = customtkinter.CTkLabel(master=lframe, text="Incorrect password entered!", font=("Helvetica Light", 10), text_color="red")

    masterpassword = customtkinter.StringVar()
    masterpassent = customtkinter.CTkEntry(master=lframe, textvariable=masterpassword, placeholder_text="Master Password", show="•", width=300)
    masterpassent.pack(padx=10, pady=10)

    authbtn = customtkinter.CTkButton(master=lframe, text="Authenticate", command=lambda: [pass_check()])
    authbtn.pack(padx=10, pady=12)

def managerScreen():
    root.title("PASSager - Password Manager")
    mframe = customtkinter.CTkScrollableFrame(master=root)
    mframe.pack(padx=20, pady=20, fill="both", expand=True)

    mainframe = customtkinter.CTkFrame(master=mframe)
    mainframe.pack(fill="both", padx=20, pady=20, expand=True)
    buttonsframe = customtkinter.CTkFrame(master=mainframe)
    buttonsframe.pack(padx=10, pady=10)

    def addpassword():
        siteAP = addpasssite_var.get()
        passAP = addpassPASS_var.get()
        PM.add_pwd(site=siteAP, password=passAP)

    def getpassword():
        siteGP = passsite_get.get()
        try:
            pass1 = PM.get_pwd(siteGP)
            getpassd.configure(text=(f"Password: {pass1}"))
            pyperclip.copy(pass1)
        except:
            getpassd.configure(text="Try Again!")

    def generatepassword():
        lengthGEN = genpassL_var.get()
        try:
            genPass = passgen(lengthI=lengthGEN)
            genpassd.configure(text=genPass)
            pyperclip.copy(genPass)
        except:
            genpassd.configure(text="Try Again!")
    
    def exitbtnfunc():
        mframe.pack_forget()
        PM.exitingFunc()
        loginScreen()

    def configFunc(func):
        if func == "theme":
            state = confvar1.get()
            if state == True:
                customtkinter.set_appearance_mode("dark")
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['theme'] = "dark"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
            elif state == False:
                customtkinter.set_appearance_mode("light")
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['theme'] = "light"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
        elif func == "temp":
            state = confvar2.get()
            if state == True:
                customtkinter.set_default_color_theme("blue")
                root.update()
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['template'] = "blue"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
            elif state == False:
                customtkinter.set_default_color_theme("green")
                root.update()
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['template'] = "green"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
        elif func == "delpass":
            state = confvar3.get()
            if state == True:
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['emergency_passdel'] = "enabled"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
            elif state == False:
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['emergency_passdel'] = "disabled"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
        elif func == "biom":
            state = confvar4.get()
            if state == True:
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['biometrics'] = "enabled"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
            elif state == False:
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['biometrics'] = "disabled"
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 

    addpassframe = customtkinter.CTkFrame(master=buttonsframe, height=150)
    addpassframe.grid(row=0, column=0, padx=10, pady=10)
    addpassimg = customtkinter.CTkImage(Image.open("assets/images/passimg.png"), size=(160, 72))
    img1 = customtkinter.CTkLabel(master=addpassframe, image=addpassimg, text="")
    img1.pack(padx=30, pady = 20)
    lbl1 = customtkinter.CTkLabel(master=addpassframe, text="Enter the Site Name", font=("Helvetica Light", 10))
    lbl1.pack()
    addpasssite_var = customtkinter.StringVar()
    addpasssiteentr = customtkinter.CTkEntry(master=addpassframe, placeholder_text="Site Name", textvariable=addpasssite_var)
    addpasssiteentr.pack(fill="both", padx=10, pady=2)
    lbl2 = customtkinter.CTkLabel(master=addpassframe, text="Enter the Password", font=("Helvetica Light", 10))
    lbl2.pack()
    addpassPASS_var = customtkinter.StringVar()
    addpassPASSentr = customtkinter.CTkEntry(master=addpassframe, placeholder_text="Password", textvariable=addpassPASS_var)
    addpassPASSentr.pack(fill="both", padx=10, pady=2)
    addpassbtn = customtkinter.CTkButton(master=addpassframe, text="Add/Update Password", font=("Helvetica Light", 10), command=lambda: [addpassword()])
    addpassbtn.pack(fill="both", padx=10, pady=10)

    getpassframe = customtkinter.CTkFrame(master=buttonsframe, height=150)
    getpassframe.grid(row=0, column=1, padx=10, pady=10)
    getpassimg = customtkinter.CTkImage(Image.open("assets/images/getpassimg.png"), size=(160, 72))
    img2 = customtkinter.CTkLabel(master=getpassframe, image=getpassimg, text="")
    img2.pack(padx=30, pady = 20)
    lbl3 = customtkinter.CTkLabel(master=getpassframe, text="Enter the Site Name", font=("Helvetica Light", 10))
    lbl3.pack()
    passsite_get = customtkinter.StringVar()
    getpasssiteentr = customtkinter.CTkEntry(master=getpassframe, placeholder_text="Site Name", textvariable=passsite_get)
    getpasssiteentr.pack(fill="both", padx=10, pady=2)
    getpassbtn = customtkinter.CTkButton(master=getpassframe, text="Get Password", font=("Helvetica Light", 10), command=lambda: [getpassword()])
    getpassbtn.pack(fill="both", padx=10, pady=10)
    getpassd = customtkinter.CTkLabel(master=getpassframe, text="Retrieved Password", font=("Helvetica Light", 15))
    getpassd.pack(fill="both", padx=10, pady=15)

    settingsbframe = customtkinter.CTkFrame(master=buttonsframe, height=150)
    settingsbframe.grid(row=1, column=0, padx=10, pady=10)
    settingsbimg = customtkinter.CTkImage(Image.open("assets/images/settingsimg.png"), size=(160, 72))
    img3 = customtkinter.CTkLabel(master=settingsbframe, image=settingsbimg, text="")
    img3.pack(padx=30, pady = 20)
    lab1 = customtkinter.CTkLabel(master=settingsbframe, text="Configuration", font=("Helvetica Light", 14))
    lab1.pack(padx=10, pady=0)

    btnsframe = customtkinter.CTkFrame(master=settingsbframe)
    btnsframe.pack(padx=10, pady=20)
    confvar1 = customtkinter.BooleanVar()
    confvar2 = customtkinter.BooleanVar()
    confvar3 = customtkinter.BooleanVar()
    confvar4 = customtkinter.BooleanVar()
    themebtn = customtkinter.CTkSwitch(master=btnsframe, text="Dark Mode", font=("Helvetica Light", 12), offvalue=False, onvalue=True, variable=confvar1, command=lambda: [configFunc("theme")])
    themebtn.pack(padx=5, anchor="w")
    tempbtn = customtkinter.CTkSwitch(master=btnsframe, text="Blue Theme", font=("Helvetica Light", 12), offvalue=False, onvalue=True, variable=confvar2, command=lambda: [configFunc("temp")])
    tempbtn.pack(padx=5, anchor="w")
    if data["theme"] == "dark":
        themebtn.select()
    if data["template"] == "blue":
        tempbtn.select()
    delpassbtn = customtkinter.CTkSwitch(master=btnsframe, text=("Delete Passwords after \n10 Incorrect Tries (Coming Soon)"), font=("Helvetica Light", 12), offvalue=False, onvalue=True, variable=confvar3, command=lambda: [configFunc("delpass")], state=DISABLED)
    delpassbtn.pack(padx=5, anchor="w")
    biobtn = customtkinter.CTkSwitch(master=btnsframe, text="Biometrics (Coming Soon!)", font=("Helvetica Light", 12), offvalue=False, onvalue=True, variable=confvar4, command=lambda: [configFunc("biom")], state=DISABLED)
    biobtn.pack(padx=5, anchor="w")
    #settingsbbtn = customtkinter.CTkButton(master=settingsbframe, text="Configuration", font=("Helvetica Light", 10))
    #settingsbbtn.pack(fill="both", padx=10, pady=41)

    genpassframe = customtkinter.CTkFrame(master=buttonsframe, height=150, width=200)
    genpassframe.grid(row=1, column=1, padx=10, pady=10)
    genpassimg = customtkinter.CTkImage(Image.open("assets/images/genpassimg.png"), size=(160, 72))
    img4 = customtkinter.CTkLabel(master=genpassframe, image=genpassimg, text="")
    img4.pack(padx=30, pady = 20)
    lbl4 = customtkinter.CTkLabel(master=genpassframe, text="Enter Length (eg. 9)", font=("Helvetica Light", 10))
    lbl4.pack()
    genpassL_var = customtkinter.StringVar()
    genpasssiteentr = customtkinter.CTkEntry(master=genpassframe, placeholder_text="Length (eg. 9)", textvariable=genpassL_var)
    genpasssiteentr.pack(fill="both", padx=10, pady=2)
    genpassbtn = customtkinter.CTkButton(master=genpassframe, text="Generate Password", font=("Helvetica Light", 10), command=lambda: [generatepassword()])
    genpassbtn.pack(fill="both", padx=10, pady=10)
    genpassd = customtkinter.CTkLabel(master=genpassframe, text="Generated Password", font=("Helvetica Light", 15))
    genpassd.pack(fill="both", padx=10, pady=15)

    #leftbarframe = customtkinter.CTkFrame(master=mainframe, height=345)
    #leftbarframe.grid(row=0, column=1, padx=10, pady=10)
    #lab = customtkinter.CTkLabel(master=leftbarframe, text="Welcome User!", font=("Helvetica Light", 15))
    #lab.pack(padx=10, pady=1)

    exitbtn = customtkinter.CTkButton(master=mainframe, text="Sign out", command=lambda: [exitbtnfunc()])
    exitbtn.pack(padx=15, pady=15)

def setUpScreen():
    root.title("PASSager - Set Up")
    sframe = customtkinter.CTkFrame(master=root)
    sframe.pack(padx=20, pady=20, fill="both", expand=True)

    def set_up():
        mps = masterpassSUI.get().encode()
        mpc = masterpassCFI.get().encode()
        if mps and mpc != "":
            if mps == mpc:
                with open("settings.json", "r+") as f:
                    data2=json.load(f)
                    data2['first_run'] = False
                    f.seek(0)
                    json.dump(data2, f, indent=4)
                    f.truncate() 
                sframe.pack_forget()
                #hashmp = hashlib.sha256(mps)
                #hexmp = hashmp.hexdigest()
                #with open("assets/files/key.hash", "w") as k:
                    #k.write(hexmp)
                loginScreen()
            else:
                errLbl2.pack_forget()
                errLbl1.pack(before=passlbl)
        else:
            errLbl1.pack_forget()
            errLbl2.pack(before=passlbl)

    image2 = customtkinter.CTkImage(Image.open("assets/images/passStart.png"), size=(235, 75))
    img2 = customtkinter.CTkLabel(master=sframe, image=image2, text="")
    img2.pack(padx=25, pady = 20)

    signlbl = customtkinter.CTkLabel(master=sframe, text="Set Up", font=("Helvetica", 20))
    signlbl.pack(padx=10, pady=12)

    passlbl = customtkinter.CTkLabel(master=sframe, text="Enter a Master Password", font=("Helvetica Light", 15))
    passlbl.pack(padx=5, pady=2)

    errLbl1 = customtkinter.CTkLabel(master=sframe, text="Passwords do not match!", font=("Helvetica Light", 10), text_color="red")

    errLbl2 = customtkinter.CTkLabel(master=sframe, text="Please enter a valid password!", font=("Helvetica Light", 10), text_color="red")

    masterpassSUI = customtkinter.StringVar()
    masterpassSU = customtkinter.CTkEntry(master=sframe, textvariable=masterpassSUI, placeholder_text="Master Password", show="•", width=300)
    masterpassSU.pack(padx=10, pady=10)

    confpasslbl = customtkinter.CTkLabel(master=sframe, text="Confirm your Master Password", font=("Helvetica Light", 15))
    confpasslbl.pack(padx=5, pady=2)

    masterpassCFI = customtkinter.StringVar()
    masterpassCF = customtkinter.CTkEntry(master=sframe, textvariable=masterpassCFI, placeholder_text="Master Password", show="•", width=300)
    masterpassCF.pack(padx=10, pady=10)

    finbtn = customtkinter.CTkButton(master=sframe, text="Finish", command=lambda: [set_up()])
    finbtn.pack(padx=10, pady=12)

if data["first_run"] == True:

    saltF = os.urandom(16)
    
    if os.stat("salt.key").st_size == 0:
        with open("salt.key", "wb") as f:
                f.write(saltF)
    setUpScreen()

else:
    loginScreen()

root.mainloop()