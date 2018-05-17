try:
    from tkinter import *
    from tkinter import ttk
except ImportError:
    from Tkinter import *
    import ttk

import Tkinter as tki
import json
import tkFileDialog

##pycrypto
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]




NORM_FONT = ("Helvetica", 10)
LARGE_FONT = ("Verdana", 13)


# Lots of Awesomeness
class getTreeFrame(Frame):

    def __init__(self, *args, **kwargs):
        Frame.__init__(self, *args, **kwargs)

        self.myFileMenu(*args)
        self.winfo_toplevel().title("Password Manager")
        self.addLists()
        self.fileName=None
        self.myPassword=None

    def addLists(self, *arg):
        #dataList = self.getData()
        headings = ["Service", "URL", "Username", "Email"]

        ####Side Menu
        sideMenu = Frame(self)
        sideMenu.pack(side=LEFT)
        ttk.Button(sideMenu, text="Open", command=lambda: self.askPassword("open")).pack(side=TOP,pady=10,padx=10)
        ttk.Button(sideMenu, text="Save", command=lambda: self.getSave()).pack(side=TOP,pady=10,padx=10)
        ttk.Button(sideMenu, text="Save As", command=lambda: self.askPassword("saveas")).pack(side=TOP,pady=10,padx=10)
        ttk.Button(sideMenu, text="Add", command=lambda: self.addEditFrame("add", None)).pack(side=TOP,pady=10,padx=10)
        ttk.Button(sideMenu, text="Delete", command=lambda: self.callDelete()).pack(side=TOP,pady=10,padx=10)
        ttk.Button(sideMenu, text="Exit", command=self.master.destroy).pack(side=TOP,pady=10,padx=10)


        
        
        scroll = ttk.Scrollbar(self, orient=VERTICAL, takefocus=True)
        self.tree = ttk.Treeview(self, columns=headings, show="headings")
        scroll.config(command=self.tree.yview)
        self.tree.configure(yscroll=scroll.set)

        scroll.pack(side=RIGHT, fill=Y)
        self.tree.pack(side=LEFT, fill='both', expand=1)

        # Adding headings to the columns and resp. cmd's
        for heading in headings:
            self.tree.heading(
                heading, text=heading,
                command=lambda c=heading: self.sortby(self.tree, c, 0))
            self.tree.column(heading, width=200)

        self.tree.bind("<Double-1>", self.OnDoubleClick)



    #Frame for add or editing
    def addEditFrame(self, myCommand, data): 
        frame = Tk()
        Tk.wm_title(frame, "Viewer")


        myID = None;

        #print "default Data:",data

        Label(frame, text="Service", width=60, bd=3, font=NORM_FONT).pack()
        service = ttk.Entry(frame, width=60)
        service.pack()

        Label(frame, width=60, bd=3, font=NORM_FONT).pack()

        Label(frame, text="URL", width=60, bd=3, font=NORM_FONT).pack()
        url = ttk.Entry(frame, width=60)
        url.pack()

        Label(frame, width=60, bd=3, font=NORM_FONT).pack()

        Label(frame, text="Username", width=60, bd=3, font=NORM_FONT).pack()
        username = ttk.Entry(frame, width=60)
        username.pack()

        Label(frame, width=60, bd=3, font=NORM_FONT).pack()
        
        Label(frame, text="Email", width=60, bd=3, font=NORM_FONT).pack()
        email = ttk.Entry(frame, width=60)
        email.pack()

        Label(frame, width=60, bd=3, font=NORM_FONT).pack()
        
        Label(frame, text="Password", width=60, bd=3, font=NORM_FONT).pack()
        password = ttk.Entry(frame, width=60)
        password.pack()


        if(data):
            self.set_text(service,data[0])
            self.set_text(url,data[1])
            self.set_text(username,data[2])
            self.set_text(email,data[3])
            self.set_text(password,data[4])

        
        
        
        B1 = ttk.Button(frame, text="Okay", command=lambda: self.addEditFrameSave(frame, myCommand,
            {
            "service":service.get(),
            "url":url.get(),
            "username":username.get(),
            "email":email.get(),
            "password":password.get()
            }))
        B1.pack(pady=10, padx=20, side="left")


        B1 = ttk.Button(frame, text="Exit", command=frame.destroy)
        B1.pack(pady=10, padx=20, side="right")

        root.mainloop()

    def addEditFrameSave(self, frame, myCommand, data):
        service = data.get("service", "")
        url = data.get("url", "")
        username = data.get("username", "")
        email = data.get("email", "")
        password = data.get("password", "")


        #if there is data to update
        if(service or url or username or password):

            #Edit, we are selecting something
  
            if(myCommand=="edit" and self.tree.selection()):
                selected_item = self.tree.selection()[0]
                self.tree.delete(selected_item)

            self.tree.insert("", "end", values=(service, url, username, email, password))

            
            frame.destroy()
        
    def set_text(self, myEntry, text):
        myEntry.delete(0,END)
        myEntry.insert(0,text)
        return


        
    def OnDoubleClick(self, event):

        curItem = self.tree.item(self.tree.focus())
        col = self.tree.identify_column(event.x)
        #print ('curItem = ', curItem)
        #print ('col = ', col)


        values =curItem.get("values", "")

        if(values):
            #pass the data into the EditFrame
            self.addEditFrame("edit",values)




    def sortby(self, tree, col, descending):
        """sort tree contents when a column header is clicked on"""
        # Grab values to sort
        data = [(tree.set(child, col), child)
                for child in tree.get_children('')]

        # Sort the data in place
        data.sort(reverse=descending)
        for ix, item in enumerate(data):
            tree.move(item[1], '', ix)
        # switch the heading cmds so it will sort in the opposite direction
        tree.heading(col,
                     command=lambda col=col: self.sortby(tree, col,
                                                         int(not descending)))





    def getTreeData(self):
        data = {}
        i = 0;
        for child in self.tree.get_children():
            cData = self.tree.item(child)["values"]
            listData = [b for b in cData]
            data.update({str(i):listData})
            i= i+1
        return data
    def getFileData(self,password):
        data = None
        myPassword=password

        try:
            with open(self.fileName, "r") as outfile:
                data = outfile.read()
         

        except:
            return None

        # If there is no data in FIle
        if not data:
            return None

        try:
            aes=AESCipher(myPassword)
            data = aes.decrypt(data)
        except:
            return "WrongPassword"
        

        
        
        data = json.loads(data)
        dataList = []

        for interator, payload in data.items():
            dataList.append(tuple(payload))

        return dataList
        

        
            

    #ask for a password   
    def askPassword(self, myCommand):

        #open the askopenfilename first
        if myCommand == "open":
            fileName = tkFileDialog.askopenfilename(title="Select a file...")
            self.fileName = fileName
            
            #To Makesure that the password is empty initially
            self.myPassword = None


            if not fileName:
                self.fileName = None
                return
        frame = Tk()
        Tk.wm_title(frame, "Password")
        Label(frame, text="Password", width=30, bd=3, font=NORM_FONT).pack()
        password = ttk.Entry(frame, show="*")
        password.pack()
        

        if myCommand == "open":
            B1 = ttk.Button(frame, text="Open", command=lambda: self.passwordOpen(frame, password.get()))
            B1.pack(pady=10, padx=20, side="left")
        elif(myCommand == "save"):
            B1 = ttk.Button(frame, text="Save")
            B1.pack(pady=10, padx=20, side="left")
        elif(myCommand == "saveas"):
            B1 = ttk.Button(frame, text="Save As", command=lambda: self.passwordSaveAs(frame, password.get()))
            B1.pack(pady=10, padx=20, side="left")
            


        B1 = ttk.Button(frame, text="Exit", command=frame.destroy)
        B1.pack(pady=10, padx=20, side="right")

        root.mainloop()


        pass



    
    def myFileMenu(self, myFrame):
        menubar = Menu(myFrame)

    #will delete a node in the tree
    def callDelete(self):
        for selected_item in self.tree.selection():
            self.tree.delete(selected_item)
        pass


    def getFileName(self):
        fileName = tkFileDialog.askopenfilename()
        self.fileName = fileName

        #To Makesure that the password is empty initially
        self.myPassword = None

        #ask for the password and will populate the data accordingly
        self.askPassword("open")

        
        #populate the List Table
        
        data = self.getFileData()
        if(data):
            for x in data:
                self.tree.insert("", "end", values=x)
        else:
            self.fileName = None #Filename is empty, for protection?

            
    def getSave(self):
        if(self.fileName):#we have a filename path
            data = self.getTreeData()
            if(data):
                #if we have the filename path, we already have the password
                #ask password logic

                myData = json.dumps(data, sort_keys=True, indent=4)
                aes=AESCipher(self.myPassword)
                encryptedData = aes.encrypt(myData)
                with open(self.fileName, "w") as outfile:
                    outfile.write(encryptedData)

        else:#We dont have a fileName, so we need to open SaveAs instead
            self.askPassword("saveas")

            

    #This is where we will Encrypt
    def passwordSaveAs(self, frame, password):

        data = self.getTreeData()
        if(data):
            f = tkFileDialog.asksaveasfile(mode='w')
            if f is None: # asksaveasfile return `None` if dialog closed with "cancel".
                return
            self.fileName =f.name

            myPassword = password
            self.myPassword = myPassword
            myData = json.dumps(data, sort_keys=True, indent=4)

            #encrypting data
            aes=AESCipher(myPassword)
            encryptedData = aes.encrypt(myData)
            f.write(encryptedData)

            #destroy the frame if its successful
            
            frame.destroy()
            f.close() 
        pass



    #This is where we will Encrypt
    def passwordOpen(self, frame, password):
        if(password):
            data = self.getFileData(password)
            if(data == "WrongPassword"):
                pass
            elif(data):
                for x in data:
                    self.tree.insert("", "end", values=x)
                self.myPassword=password
                frame.destroy()
            else:
                self.fileName = None #Filename is empty, for protection?


        

root = Tk()
mainMenu = getTreeFrame(root, bd=3).pack()
root.mainloop()
