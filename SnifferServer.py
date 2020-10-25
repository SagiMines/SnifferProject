import socket
import pyodbc
from tkinter import *
import tkinter.messagebox
from tkinter.ttk import *
from tkinter import scrolledtext
import time
import threading

global G
UDP_IP = '10.100.102.7'
UDP_PORT = 5005
BUFFER_SIZE = 1000000
ROOT = Tk()

def receive_message():
    """
    This function receives the message from the client and decote it into str and then into list.
    After that the function send the necessary data to SQL server and shows the data on the GUI platform.
    return: None
    """
    global G
    s =socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((UDP_IP, UDP_PORT))
    G.insert(INSERT, "Welcome to the 'Sniffer' server")
    ROOT.update()# updates the Tkinter form
    G.insert(INSERT, "\n")
    while 1:
        data = s.recv(BUFFER_SIZE)
        if not data:
            break
        data = data.decode()
        if ("ip" not in format(data) and format(data).count('$') == 3):
            sql = format(data)
            sqllist = list(sql.split("$"))
            sqllist = [sqllist]
            sql_connection(sqllist)
        elif ("ip" not in format(data) and format(data).count('$') == 4):
            sql = format(data)
            sqllist = list(sql.split("$"))
            sqllist = [sqllist]
            sql_connection2(sqllist)
        if ("$" not in format(data)):
            G.insert(INSERT, format(data))
            ROOT.update()  # updates the Tkinter form
            time.sleep(1)
            G.insert(INSERT, "\n")

def sql_connection(data):
    """
    This function send the user data received from the client into a SQL database server.
    return: None
    """
    #define the server name and the database name
    server = '.'
    database = 'Boss sniffer'

    # define our connection string
    cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server}; \
                           SERVER=' + server + '; \
                           DATABASE=' + database +';\
                           Trusted_Connection=yes;')

    #create the connection cursor
    cursor = cnxn.cursor()

    #define our insert query
    insert_query = '''INSERT INTO user_data1 (user_time, user_ip, cmp_name, mac) 
                      VALUES (?, ?, ?, ?);'''
    #loop through each row in the matrix
    for row in data:
        #define the values to insert
        values = (row[0],row[1],row[2],row[3])
        #insert the data into the database
        cursor.execute(insert_query, values)

    #commit the inserts
    cnxn.commit()

    #grab all the rows in our database table
    cursor.execute('SELECT * FROM user_data1')

    #loop through the results
    #for row in cursor:
       # print(row)

def sql_connection2(data):
    """
    This function send the user web data received from the client into a SQL database server.
    return: None
    """
    #define the server name and the database name
    server = '.'
    database = 'Boss sniffer'

    # define our connection string
    cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server}; \
                           SERVER=' + server + '; \
                           DATABASE=' + database +';\
                           Trusted_Connection=yes;')

    #create the connection cursor
    cursor = cnxn.cursor()

    #define our insert query
    insert_query = '''INSERT INTO Web_info (src_ip, src_port, dst_ip, dst_port,src_mac) 
                      VALUES (?, ?, ?, ?, ?);'''
    #loop through each row in the matrix
    for row in data:
        #define the values to insert
        values = (row[0],row[1],row[2],row[3],row[4])
        #insert the data into the database
        cursor.execute(insert_query, values)

    #commit the inserts
    cnxn.commit()

    #grab all the rows in our database table
    cursor.execute('SELECT * FROM Web_info')

    #loop through the results
   # for row in cursor:
        #print(row)

def set_GUI():
    """
    This function sets the Tkinter platfom
    return: tkinter.scrolledtext.ScrolledText
    """
    ROOT.title('Sniffer Server')
    ROOT.iconbitmap(r'C:\Users\sagi1\PycharmProjects\untitled6\venv\BOSSSNIFFER\boss 2\Photos\Sniffer Icon.ico')
    ROOT.geometry("1100x800")
    txt = scrolledtext.ScrolledText(ROOT, width = 135, height = 50)
    txt.grid(column = 1, row = 1)
    return txt



def main():
    global G
    G=set_GUI()
    threading.Thread(target=receive_message, daemon=True).start()
    ROOT.mainloop()



if __name__=='__main__':
    main()