#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  SecureMsj
#
#  Copyright (C) 2013 Ricardo Gallegos *RickGC*
#
#  SecureMsj is free software; you can redistribute it and/or modify it under
#  the terms of the GNU General Public License version 2, as published by the
#  Free Software Foundation
#
#  SecureMsj is distributed in the hope that it will be useful, but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
#  details (http://www.gnu.org/licenses/gpl.txt).
#
#  You should have received a copy of the GNU General Public License
#  along with sapyto-Public_Edition; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# Written by RickGC
# Herramienta para encriptar y desencriptar textos o mensajes para transmitirlos de forma segura
# Que por naturaleza queremos que solo la persona que deba verlos los vea, y no un tercero
# Como por ejemplo pasar una password por Skype, escribir el numero de una tarjeta de credito
# Por Facebook, escribir secretos o cosas importante por mensjes de twitter etc.

##########################################
__Autor__ = ['Ricardo Gallegos Cortzar'] #
__Email__ = ['RickGC[at]gmail[dot]com']  #
__tw__   = ['@0xRickGC']                 #
__web__   = ['']                         #
##########################################

import sys # Usamos la libreria para identificar la plataforma operativa
import base64 # Libreria para la codificacion de mensajes
import time # Libreria para control de tiempo
from time import sleep # De la lib time solo importamos el modulo sleep, para hacer el delay

sistema_operativo = sys.platform # Identificamos la plataforma operativa en el que se usa la aplicacion

# Probamos importar la libreria para la encripcion o desencripcion
try:
    from Crypto.Cipher import AES
except ImportError:                # Si al importarla se recibe un error es que no esta instalada la libreria.
    print "[!] No se encontro instalada la libreria 'Pycrypto' en su sistema operativo"
    print "[!] Esta libreria es necesaria para la aplicacion de criptografia al texto o msj"
    # Preguntamos si desea que ayudemos con la instalacion de la lib.
    install_pycrypto = raw_input("[+] Desea que la aplicacion le ayude a descargar de la libreria? [s/n]: ")
    if install_pycrypto == "s" or install_pycrypto == "si" or install_pycrypto == "Si" or install_pycrypto == "SI":
        # Si el sistema operativo es un Mac OS X Descargamos el siguiente paquete
        if sistema_operativo == "darwin":
            print "[-] Descargue e instale la siguiente libreria..."
            sleep(1.5)
            subprocess.Popen("open https://rudix.googlecode.com/files/pycrypto-2.4.1-0.pkg", shell=True).wait()
            raw_input("[*] Una ves instalada presione [Enter] para continuar...")
        # Si es GNU/Linux bajamos el siguiente paquete
        elif sistema_operativo == "linux2":
            print "[-] Descargue e instale la siguiente libreria..."
            sleep(1.5)
            subprocess.Popen("firefox http://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.tar.gz", shell=True).wait()
            raw_input("[*] Una ves instalada presione [Enter] para continuar...")
        # Si es MS Windows Bjamos el siguiente paquete
        elif sistema_operativo == "win32":
            print "[-] Descargue e instale la siguiente libreria..."
            sleep(1.5)
            subprocess.Popen('start "%ProgramFiles%\Internet Explorer\iexplore.exe" "http://www.voidspace.org.uk/cgi-bin/voidspace/downman.py?file=pycrypto-2.0.1.win32-py2.5.zip"', shell=True).wait()
            raw_input("[*] Una ves instalada presione [Enter] para continuar...")
        # Si no es ningun sistema operativo compatible terminamos.
        else:
            print "[!] Sistema operativo no compatible"
            raw_input("[*] Presiona [ENTER] para terminar...")
            sys.exit()

global KeySecreta # Variable global para setear una Keytemporal
KeySecreta = ""

# Metodo para recibir la variable key
def RecibirKey():
    if KeySecreta == "":
        print  "[!] Nota: La Key debe ser de 32 caracteres, para AES-256"
        global key
        key = raw_input("[!] Ingrese la Key a usar, para trabajar: ") # Recibimos la variable Key
        while len(key) != 32: # Mientras el tamanio la variable key sea diferente de 32 caracteres, vuelve a pedir la variable key.
            print "[!] La key no contiene 32 caracteres"
            print "[!] La key debe tener 32 caracteres para poder encriptar con AES256"
            print "[!] Purebe deneuvo..."
            sleep(.5)
            key = raw_input("[-] Reingrese la Key a usar, para trabajar: ")
    else:
        key = KeySecreta


# Metodo para generar cadenas de caracteres aleatorios (Generador de Keys)
def Generador_Key():
    tam = 32 # la variable tam sera el numero de caracteres para la key de AES-256
    caracteres = string.ascii_letters+string.digits+string.punctuation # La variable caracteres podra contener letras numeros o simbolos especiales
    key_generada = ''.join([random.choice(caracteres) for _ in range(tam)]) # Genera la aleatorizacion de numeros letras y caracteres especiales
    print "[*] Se genero esta nueva Key:\n"
    print key_generada
    print ""
    raw_input("[*] Presiona [ENTER] para continuar.")


# Metodo para establecer una key temporal
def setKey():
    key = raw_input("[-] Ingrese la Key a usar para todo el cifrado AES256 de la sesion: ")
    while len(key) != 32: # Mientras el tamanio la variable key sea diferente de 32 caracteres, vuelve a pedir la variable key.
    	print "[!] La key no contiene 32 caracteres"
		print "[!] La key debe tener 32 caracteres para poder encriptar con AES256"
		print "[!] Purebe deneuvo..."
		sleep(.5)
		key = raw_input("[-] Reingrese la Key a usar, para trabajar: ")
    global KeySecreta
    KeySecreta = key
    print "[*] La Key se configuro correctamente."
    raw_input("[*] Presiona [ENTER] para continuar.")

# Metodo de Encriptacion de Texto
def encriptarTEXTO():
    # Recibimos la key atraves del metodo
    RecibirKey()
    # Recibimos el texto a encriptar
    texto = raw_input("[-] Ingrese el texto a encriptar con AES: ")
    
    # El caracter utilizado para el relleno - con un cifrado de bloques tales como AES, el valor a
    # Cifrar debe ser un múltiplo de block_size de longitud. Este caracter se
    # Utiliza para asegurarse de que su valor es siempre un múltiplo de block_size
    PADDING = '{'
	
    # Tamaño del bloque de encripcion para el objeto de la variable cipher; podria ser 16, 24 o 32 para AES
    BLOCK_SIZE = 32
    
    # Funcion para rellenar el texto a cifrar
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
    a = 50 * 5
	
    # Linea de codigo para Encriptar y codificar un string (nuestro mensaje)
    # Encriptamos con AES; Codificamos con Base64.
    CodificarAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	
    # Genera el cifrado inyectandole la variable "key"
    cipher = AES.new(key)
    
    # Variable para devolver el mensaje encriptado
    aes = CodificarAES(cipher, texto)
    print chr(27)+"[1;32m"+"[*] "+chr(27)+"[0m"+"Este es tu mensaje enciptado via AES:\n"
    print str(aes)
    print ""
    raw_input(chr(27)+"[1;32m"+"[*] "+chr(27)+"[0m"+"Presiona [ENTER] para continuar.")


# Metodo de Desencriptacion Texto
def desencriptarTEXTO():
    # Recibimos la Key atraves del metodo
    RecibirKey()
    # Recibimos el texto a desencriptar
    texto = raw_input("[-] Ingrese el texto a desencriptar con AES: ")
    
    # El caracter utilizado para el relleno - con un cifrado de bloques tales como AES, el valor a
    # Cifrar debe ser un múltiplo de block_size de longitud. Este caracter se
    # Utiliza para asegurarse de que su valor es siempre un múltiplo de block_size
    PADDING = '{'
	
    # Tamaño del bloque de encripcion para el objeto de la variable cipher; podria ser 16, 24 o 32 para AES
    BLOCK_SIZE = 32
	
    # Funcion para rellenar el texto a cifrar
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
    a = 50 * 5
	
    # Linea de codigo para Desencriptar y decodificar un string (nuestro mensaje)
    # Desencriptamos con AES; Decodificamos con Base64.
    DecodificarAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	
    # Genera el cifrado inyectandole la variable "key"
    cipher = AES.new(key)
    
    # Variable para devolver el mensaje encriptado
    aes = DecodificarAES(cipher, texto)
    print "[*] Este es tu mensaje desenciptado via AES:\n"
    print str(aes)
    print ""
    raw_input("[*] Presiona [ENTER] para continuar.")


def encriptarARCHIVO():
    # Recibimos la key ataraves del metodo
    RecibirKey()
    archivo = raw_input("[-] Ingrese la ruta del archivo a encriptar con AES256: ")
    archivo = file(archivo, "r")
    archivo = archivo.read()
	
    PADDING = '{'
	
    BLOCK_SIZE = 32
	
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
    a = 50 * 5
	
	
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	
    cipher = AES.new(key)
	
    aes = EncodeAES(cipher, archivo)
	
    creararchivo = file("archivo_encriptado.docx", "w")
    creararchivo.write(aes)
    creararchivo.close()
    print "[*] Tu archivo fue encriptado correctamente!"
    raw_input("[*] Presiona [ENTER] para continuar.")


def desencriptarARCHIVO():
    # Recibimos la key ataraves del metodo
    RecibirKey()
    archivo = raw_input("[-] Ingrese la ruta del archivo a desencriptar con AES256: ")
    archivo = file(archivo, "r")
    archivo = archivo.read()
    PADDING = '{'
	
    BLOCK_SIZE = 32
	
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
    a = 50 * 5
	
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	
    cipher = AES.new(key)
	
    aes = DecodeAES(cipher, archivo)
    creararchivo = file("archivo_desencriptado.docx", "w")
    creararchivo.write(aes)
    creararchivo.close()
    print "Se desencripto correctamente este archivo!"


# Metodo para imprimir nuestro banner ;)
def banner():
	print """
		 ____                             __  __      _
		/ ___|  ___  ___ _   _ _ __ ___  |  \/  |___ (_)
		\___ \ / _ \/ __| | | | '__/ _ \ | |\/| / __|| |
		 ___) |  __/ (__| |_| | | |  __/ | |  | \__ \| |
		|____/ \___|\___|\__,_|_|  \___| |_|  |_|___// |
		                                            |__/"""
	print """
	      Encripta/Desencripta y Codifica/Decodifica
	  texto, mensajes, documentos o archivos importantes
	Via Advanced Encryption Standard 256 & Base64 algorithm
	Corre en:OS X 10.5-10.8, Linux Kernel 2-3 y Windows XP/Vista/7/8
	             Autor: Ricardo Gallegos *RickGC*
	                     Version: [2.0]"""

# Menu Principal
def menu():
	try:
		banner()
		print "\n[>] 1. Encriptar un mensaje."
		print "[>] 2. Desencriptar un mensaje."
		print "[>] 3. Encriptar un archivo."
		print "[>] 4. Desencriptar un archivo."
		print "[>] 5. Generar una Key."
		print "[>] 6. Establecer una Key temporal"
		print "\n[>] 00. Regresar al menu anterior."
		op = raw_input("\n[-] Porfavor elija una opcion: ")
        
		if op == "1":
			encriptarTEXTO()
			menu()
		elif op == "2":
			desencriptarTEXTO()
			menu()
		elif op == "3":
			encriptarARCHIVO()
			menu()
		elif op == "4":
			desencriptarARCHIVO()
			menu()
		elif op == "5":
			Generador_Key()
			menu()
		elif op == "6":
			setKey()
			menu()
		elif op == "00":
			print "[!] Terminado Secure Msj..."
			sleep(.5)
			sys.exit()
		else:
			print "[!] Opcion incorrecta pruebe denuevo...\n"
			sleep(1.2)
			menu()
    
	except KeyboardInterrupt:
		print "\n[*] Ok, Saliendo de Secure Msj..."
		sleep(.5)
		sys.exit()

# Como el modulo no se esta importanto a otro programa comprobamos que que corre solo y corremos el menu principal.
if __name__ == "__main__":
    menu()

