from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import psycopg2
from smb.SMBConnection import SMBConnection
import os
import logging
import socket
import paramiko


# configure logging 
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = ''


# PostgreSQL database configuration
db_config = {
    'dbname': '',
    'user': '',
    'password': '',
    'host': 'dp-ip',
    'port': 5432
}

def get_db_connection():
    conn = psycopg2.connect(**db_config)
    return conn


def list_samba_share_contents(share_name, username, password):
    client_machine_name = socket.gethostname()
    server_machine_name = ''


    conn = SMBConnection(username, password, client_machine_name, server_machine_name, use_ntlm_v2=True)
    conn.connect('IP_AD', 139)


    shared_files = []
    for file_info in conn.listPath(share_name, '/'):
        shared_files.append(file_info.filename)
    return shared_files    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_user', methods=['POST'])
def add_user():
    try:
         # log the entire request form data
        logging.debug("form data : %s", request.form.to_dict())


        username = request.form['username']
        password = request.form['password']

        # log individual form data
        logging.debug("Username: %s", username)
        logging.debug("Password: %s", password)

        if not username or not password:
            flash('Username and password are required!', 'danger')
            return redirect(url_for('index'))

   
    
       # Hash the password for storing in the database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
        try:


        # Connect to PostgreSQL database
            conn = get_db_connection()
            cursor = conn.cursor()
        # check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                flash('Username already exist!', 'danger')
                return redirect(url_for('index'))
        

        # Insert user credentials into the database
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            conn.commit()
            cursor.close()
            conn.close()

        # Add the user to samba and set the password 
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect('', username='', password='')
            command = f'echo "" | sudo -S /usr/local/bin/add_samba_user.sh {username} {password}'
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()
            
            
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode()
            error = stderr.read().decode()
            ssh.close()



            logging.debug("SSH command executed: %s", command)
            logging.debug("SSH command output: %s", output)
            logging.debug("SSH command error: %s", error)

            if exit_status == 0:
                flash('User added succesfully!', 'success')
                return redirect(url_for('sambaserv', username=username, password=password))
            else:
                flash(f'Failed to add user to samba: {error}', 'danger')
        except psycopg2.Error as err:    
            flash(f'Database error: {err}', 'danger')
        except paramiko.SSHException as e:
            flash(f'Failed to add user to Samba: {e}', 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        logging.error("Error in add_user: %s", e)
        flash('An error occured while processing your request', 'danger')
        return redirect(url_for('index'))


      
@app.route('/sambaserv')
def sambaserv():
    try:
        share_name = 'shared'
        server_ip = ''
        username = ''
        password = ''
        contents = list_samba_share_contents(share_name, server_ip, username, password)
        return render_template('sambserv.html', contents=contents )
    except Exception as e:
        flash(f'Error retrieving Samba share contents: {e}', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 
    app.debug = True     
