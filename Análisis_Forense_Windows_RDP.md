# CTF - Análisis Forense Windows via RDP

## Tabla de Contenidos
1. [Introducción y Metodología](#introducción-y-metodología)
2. [Conexión Inicial y Reconocimiento](#conexión-inicial-y-reconocimiento)
3. [Enumeración de Usuarios](#enumeración-de-usuarios)
4. [Análisis de Carpetas y Permisos](#análisis-de-carpetas-y-permisos)
5. [Análisis de Servicios](#análisis-de-servicios)
6. [Análisis de Procesos](#análisis-de-procesos)
7. [Programas de Inicio](#programas-de-inicio)
8. [Configuración de Firewall](#configuración-de-firewall)
9. [Gestión de Red y Puertos](#gestión-de-red-y-puertos)
10. [Técnicas de Comunicación](#técnicas-de-comunicación)
11. [Comandos de Referencia](#comandos-de-referencia)
12. [Troubleshooting y Técnicas Avanzadas](#troubleshooting-y-técnicas-avanzadas)

---

## Introducción y Metodología

### Objetivo del CTF
Este manual cubre la metodología para realizar análisis forense en sistemas Windows a través de RDP, con enfoque en:
- **Reconocimiento de sistema**
- **Enumeración de usuarios y permisos**
- **Análisis de servicios y procesos**
- **Configuración de red y comunicaciones**
- **Detección de artefactos de seguridad**

### Información del Entorno
- **IP Target**: `172.20.16.137`
- **Usuario**: `Administrator`
- **Contraseña**: `password123`
- **Protocolo**: RDP (Remote Desktop Protocol)
- **Puerto**: `3389` (por defecto)

### Metodología de Análisis
1. **Reconocimiento inicial**: Conexión y verificación de acceso
2. **Enumeración de usuarios**: Identificación de cuentas locales
3. **Análisis de permisos**: Verificación de ACLs y permisos de archivos
4. **Análisis de servicios**: Estado y configuración de servicios del sistema
5. **Análisis de procesos**: Procesos en ejecución y análisis de memoria
6. **Persistencia**: Programas de inicio y tareas programadas
7. **Red y firewall**: Configuración de conectividad y reglas de seguridad

---

## Conexión Inicial y Reconocimiento

### Conexión RDP
```bash
# Desde Linux
xfreerdp /u:Administrator /p:password123 /v:172.20.16.137
rdesktop -u Administrator -p password123 172.20.16.137

# Desde Windows
mstsc /v:172.20.16.137
```

### Verificación de Conectividad
```cmd
# Verificar conectividad de red
ping 172.20.16.137

# Verificar puerto RDP abierto
nmap -p 3389 172.20.16.137
telnet 172.20.16.137 3389
```

### Reconocimiento Inicial del Sistema
```cmd
# Información del sistema
systeminfo
hostname
whoami
whoami /priv
whoami /groups

# Versión de Windows
ver
wmic os get caption,version,buildnumber

# Arquitectura del sistema
wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%

# Información de red básica
ipconfig /all
arp -a
route print
```

---

## Enumeración de Usuarios

### Comandos Básicos de Usuario
```cmd
# Listar todos los usuarios locales
net user

# Información detallada de usuario específico
net user Administrator
net user Becket

# Usuarios activos
query user
quser

# Grupos locales
net localgroup

# Miembros de grupos específicos
net localgroup Administrators
net localgroup "Remote Desktop Users"
```

### Análisis Avanzado de Usuarios
```cmd
# Historial de inicio de sesión (requiere eventos)
wevtutil qe Security /c:50 /f:text /q:"*[System[(EventID=4624)]]"

# Políticas de contraseña
net accounts

# Sesiones RDP activas
qwinsta
query session

# Usuarios con privilegios de inicio de sesión como servicio
whoami /priv | findstr SeServiceLogonRight
```

### PowerShell para Enumeración de Usuarios
```powershell
# Usuarios locales con PowerShell
Get-LocalUser
Get-LocalUser | Where-Object {$_.Enabled -eq $True}

# Grupos y membresías
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"

# Perfiles de usuario
Get-WmiObject -Class Win32_UserProfile | Select-Object LocalPath,LastUseTime,Special
```

---

## Análisis de Carpetas y Permisos

### Navegación y Análisis de Permisos
```cmd
# Navegar a la carpeta objetivo
cd "C:\Users\Administrator\Desktop"
dir

# Verificar permisos con icacls
icacls myprograms
icacls "C:\Users\Administrator\Desktop\myprograms" /t

# Permisos detallados
icacls "C:\Users\Administrator\Desktop\myprograms" /t /c > permisos.txt
```

### Interpretación de Permisos ICACLS
```cmd
# Códigos de permisos comunes:
# F  = Full access (control total)
# M  = Modify access (modificar)
# RX = Read and execute access (leer y ejecutar)
# R  = Read-only access (solo lectura)
# W  = Write-only access (solo escritura)
# D  = Delete access (eliminar)

# Ejemplo de análisis
icacls "C:\Users\Administrator\Desktop" /t
```

### Análisis Recursivo de Permisos
```cmd
# Buscar archivos con permisos específicos
icacls "C:\Users\*" /findsid Administrator /t

# Buscar archivos modificables por todos
icacls "C:\Program Files" /t | findstr "Everyone:(F)"
icacls "C:\Program Files (x86)" /t | findstr "Everyone:(F)"

# Verificar permisos en carpetas críticas
icacls "C:\Windows\System32"
icacls "C:\Windows\Temp"
```

### PowerShell para Análisis de Permisos
```powershell
# Obtener ACL de archivos/carpetas
Get-Acl "C:\Users\Administrator\Desktop\myprograms" | Format-List

# Buscar archivos con permisos específicos
Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object {(Get-Acl $_.FullName).Access | 
    Where-Object {$_.IdentityReference -match "Everyone" -and $_.FileSystemRights -match "FullControl"}}
```

---

## Análisis de Servicios

### Consulta de Servicios
```cmd
# Consultar servicio específico
sc query StrikerEureka
sc queryex StrikerEureka

# Información detallada del servicio
sc qc StrikerEureka

# Todos los servicios
sc query
net start
```

### Análisis del Servicio StrikerEureka
Según la información proporcionada, el servicio debe mostrar:
```
SERVICE_NAME: StrikerEureka
TYPE         : 10  WIN32_OWN_PROCESS  
STATE        : 1  STOPPED  
WIN32_EXIT_CODE : 1077 (0x435)
SERVICE_EXIT_CODE : 0 (0x0)
CHECKPOINT   : 0x0
WAIT_HINT    : 0x0
```

### Interpretación de Estados de Servicio
```cmd
# Estados posibles:
# 1 = STOPPED
# 2 = START_PENDING
# 3 = STOP_PENDING
# 4 = RUNNING
# 5 = CONTINUE_PENDING
# 6 = PAUSE_PENDING
# 7 = PAUSED

# Códigos de error comunes:
# 1077 = ERROR_SERVICE_NEVER_STARTED
# 0    = ERROR_SUCCESS
```

### Análisis Avanzado de Servicios
```cmd
# Servicios en ejecución
sc query state=all
sc query type=service state=all

# Servicios con rutas sospechosas
wmic service get name,displayname,pathname,startmode

# Servicios que se ejecutan como usuario específico
sc query | findstr "SERVICE_NAME"

# Configuración de inicio de servicios
sc config StrikerEureka
```

### PowerShell para Servicios
```powershell
# Obtener servicios
Get-Service
Get-Service -Name "StrikerEureka"

# Servicios detenidos
Get-Service | Where-Object {$_.Status -eq "Stopped"}

# Información detallada WMI
Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "StrikerEureka"} | Format-List *
```

---

## Análisis de Procesos

### Comandos Básicos de Procesos
```cmd
# Listar todos los procesos
tasklist
tasklist /v
tasklist /svc

# Procesos de usuario específico
tasklist /fi "username eq Administrator"

# Procesos por uso de memoria
tasklist /fi "memusage gt 100000"
```

### Análisis de Procesos Críticos
```cmd
# Procesos típicos esperados:
# - explorer.exe (Windows Explorer)
# - cmd.exe (Command Prompt)
# - svchost.exe (Service Host - múltiples instancias)
# - winlogon.exe (Windows Logon)
# - csrss.exe (Client Server Runtime Process)
# - smss.exe (Session Manager)
# - wininit.exe (Windows Initialization)

# Verificar procesos del sistema
tasklist | findstr "explorer.exe"
tasklist | findstr "svchost.exe"
tasklist | findstr "cmd.exe"
```

### Análisis de Red por Proceso
```cmd
# Conexiones de red por proceso
netstat -ano
netstat -ano | findstr ESTABLISHED
netstat -ano | findstr LISTENING

# Relacionar PID con proceso
tasklist | findstr "PID_NUMERO"
```

### PowerShell para Análisis de Procesos
```powershell
# Procesos con información extendida
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet

# Procesos con conexiones de red
Get-NetTCPConnection | Group-Object -Property OwningProcess | 
    ForEach-Object {
        $process = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ProcessName = $process.ProcessName
            PID = $_.Name
            Connections = $_.Count
        }
    }

# Procesos sospechosos (ubicaciones inusuales)
Get-Process | Where-Object {$_.Path -notlike "*Windows*" -and $_.Path -notlike "*Program Files*"}
```

---

## Programas de Inicio

### Ubicaciones de Startup
```cmd
# Carpeta Startup del usuario Administrator
dir "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

# Carpeta Startup global (todos los usuarios)
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

# Startup desde registro
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Programas Detectados Según CTF
Según la información, se esperan encontrar:
- **jaeger**
- **windows security notifications**

### Análisis Completo de Persistencia
```cmd
# Registro - Run keys
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v

# Servicios que inician automáticamente
sc query | findstr "AUTO_START"
wmic service where StartMode="Auto" get Name,DisplayName,PathName

# Tareas programadas
schtasks /query /fo LIST /v
```

### PowerShell para Startup
```powershell
# Programas de inicio con WMI
Get-WmiObject Win32_StartupCommand | Select-Object Name, command, Location, User

# Desde registro
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Tareas programadas
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
```

---

## Configuración de Firewall

### Consulta de Reglas de Firewall
```cmd
# Ver todas las reglas del firewall
netsh advfirewall firewall show rule name=all

# Reglas específicas por nombre
netsh advfirewall firewall show rule name="nc"
netsh advfirewall firewall show rule name=nc

# Estado del firewall
netsh advfirewall show allprofiles
```

### Análisis de Reglas Sospechosas
Según el CTF, buscar reglas relacionadas con **nc** (netcat):
```cmd
# Filtrar reglas de nc
netsh advfirewall firewall show rule name=all | findstr "nc"
netsh advfirewall firewall show rule name=all | findstr "5000"
netsh advfirewall firewall show rule name=all | findstr "4444"
```

**Regla esperada:**
- **Enabled**: Yes
- **Direction**: In
- **Profiles**: Private,Public
- **Protocol**: TCP/UDP
- **LocalPort**: Any
- **Action**: Allow

### Gestión de Reglas de Firewall
```cmd
# Agregar regla para puerto 5000 - perfil Domain
netsh advfirewall firewall add rule name="nc-domain" dir=in action=allow protocol=TCP localport=5000 profile=domain

# Agregar regla para puerto 4444 - perfil Domain
netsh advfirewall firewall add rule name="nc-domain" dir=in action=allow protocol=TCP localport=4444 profile=domain

# Eliminar regla
netsh advfirewall firewall delete rule name="nc-domain"

# Modificar regla existente
netsh advfirewall firewall set rule name="nc" new enable=yes
```

### PowerShell para Firewall
```powershell
# Reglas de firewall
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*nc*"}
Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound" -and $_.Action -eq "Allow"}

# Crear nueva regla
New-NetFirewallRule -DisplayName "Allow TCP 5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

---

## Gestión de Red y Puertos

### Verificación de Puertos
```cmd
# Puertos en escucha
netstat -an | find "5000"
netstat -an | find "4444"
netstat -an | find "LISTENING"

# Puertos específicos
netstat -an | findstr ":5000"
netstat -an | findstr ":4444"
```

### Pruebas de Conectividad
```cmd
# Ping a objetivo
ping 172.20.16.137

# Telnet para verificar puerto
telnet 172.20.16.137 5000
telnet 172.20.16.137 4444

# PowerShell para test de puerto
powershell Test-NetConnection -ComputerName 172.20.16.137 -Port 5000
```

### Configuración de Interface de Red
```cmd
# Configuración IP
ipconfig /all

# Tabla de enrutamiento
route print

# Tabla ARP
arp -a

# Caché DNS
ipconfig /displaydns
```

---

## Técnicas de Comunicación

### Problema con Netcat
Según el CTF, el comando `nc` no es reconocido en Windows. Alternativas:

### PowerShell TCP Listener
```powershell
# Crear listener TCP en puerto 5000
$listener = [System.Net.Sockets.TcpListener]5000
$listener.Start()
$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
while(($line = $reader.ReadLine()) -ne $null) { 
    Write-Output $line 
}
```

### PowerShell TCP Client
```powershell
# Conectar como cliente
$client = New-Object System.Net.Sockets.TcpClient("172.20.16.137",5000)
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true
$writer.WriteLine("Mensaje de prueba")
```

### Alternativas a Netcat en Windows
```cmd
# Usar telnet como cliente básico
telnet 172.20.16.137 5000

# PowerShell Web Request
powershell Invoke-WebRequest -Uri "http://172.20.16.137:5000" -Method POST -Body "test"
```

### Verificación de Listener Activo
```cmd
# Verificar que el puerto esté en escucha
netstat -an | findstr ":5000"

# Verificar proceso que usa el puerto
netstat -ano | findstr ":5000"
```

---

## Comandos de Referencia

### Comandos Esenciales Windows

#### Red y Conectividad
```cmd
# Configuración de red
ipconfig /all                                    # Configuración IP completa
ping [IP]                                        # Test de conectividad
tracert [IP]                                     # Rastreo de ruta
nslookup [domain]                                # Resolución DNS
arp -a                                           # Tabla ARP
route print                                      # Tabla de enrutamiento
netstat -an                                      # Conexiones de red
netstat -ano                                     # Conexiones con PID
netstat -an | findstr [PORT]                     # Filtrar por puerto
```

#### Usuarios y Grupos
```cmd
net user                                         # Listar usuarios
net user [username]                              # Info de usuario específico
net localgroup                                  # Listar grupos locales
net localgroup [groupname]                      # Miembros de grupo
whoami                                          # Usuario actual
whoami /priv                                    # Privilegios actuales
whoami /groups                                  # Grupos actuales
query user                                      # Usuarios conectados
```

#### Archivos y Permisos
```cmd
dir [path]                                      # Listar archivos
icacls [path]                                   # Ver permisos
icacls [path] /t                                # Permisos recursivos
icacls [path] /grant [user]:[perm]              # Otorgar permisos
attrib [file]                                   # Atributos de archivo
where [filename]                                # Buscar archivo
```

#### Procesos y Servicios
```cmd
tasklist                                        # Listar procesos
tasklist /svc                                   # Procesos con servicios
tasklist /fi "imagename eq [process]"           # Filtrar proceso
taskkill /f /im [process]                       # Terminar proceso
sc query [service]                              # Estado de servicio
sc start [service]                              # Iniciar servicio
sc stop [service]                               # Detener servicio
sc config [service]                             # Configurar servicio
```

#### Firewall
```cmd
netsh advfirewall show allprofiles              # Estado del firewall
netsh advfirewall firewall show rule name=all  # Todas las reglas
netsh advfirewall firewall show rule name=[name] # Regla específica
netsh advfirewall firewall add rule name="[name]" dir=in action=allow protocol=TCP localport=[port] # Agregar regla
netsh advfirewall firewall delete rule name="[name]" # Eliminar regla
```

#### Sistema
```cmd
systeminfo                                      # Información del sistema
hostname                                        # Nombre del host
ver                                            # Versión de Windows
wmic os get caption,version,buildnumber         # Info del OS
wmic process list                               # Procesos WMI
wmic service list                               # Servicios WMI
```

### Comandos PowerShell Equivalentes

#### Información del Sistema
```powershell
Get-ComputerInfo                                # Información completa
Get-WmiObject -Class Win32_OperatingSystem      # Info del OS
Get-WmiObject -Class Win32_ComputerSystem       # Info del hardware
```

#### Red
```powershell
Get-NetIPConfiguration                          # Configuración IP
Get-NetTCPConnection                           # Conexiones TCP
Get-NetUDPEndpoint                             # Endpoints UDP
Test-NetConnection -ComputerName [IP] -Port [port] # Test de puerto
```

#### Procesos y Servicios
```powershell
Get-Process                                     # Listar procesos
Get-Service                                     # Listar servicios
Get-Process | Where-Object {$_.ProcessName -eq "[name]"} # Filtrar proceso
Start-Service -Name "[service]"                 # Iniciar servicio
Stop-Service -Name "[service]"                  # Detener servicio
```

#### Usuarios y Permisos
```powershell
Get-LocalUser                                   # Usuarios locales
Get-LocalGroup                                  # Grupos locales
Get-LocalGroupMember -Group "[group]"           # Miembros de grupo
Get-Acl "[path]"                               # Permisos de archivo
```

---

## Troubleshooting y Técnicas Avanzadas

### Problemas Comunes

#### Netcat No Disponible
```cmd
# Error: 'nc' is not recognized
# Solución 1: Usar PowerShell TCP
powershell -Command "$l=[System.Net.Sockets.TcpListener]5000;$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();$r=New-Object System.IO.StreamReader($s);while(($line=$r.ReadLine()) -ne $null){Write-Output $line}"

# Solución 2: Descargar netcat
# wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
# O usar ncat de Nmap
```

#### Problemas de Conectividad
```cmd
# Verificar estado del firewall
netsh advfirewall show allprofiles

# Deshabilitar firewall temporalmente (solo para testing)
netsh advfirewall set allprofiles state off

# Verificar si el puerto está bloqueado
telnet 127.0.0.1 5000
```

#### Permisos Insuficientes
```cmd
# Ejecutar como administrador
runas /user:administrator cmd

# Verificar privilegios actuales
whoami /priv
```

### Técnicas de Análisis Forense

#### Análisis de Logs
```cmd
# Event Viewer desde línea de comandos
eventvwr.msc

# Logs específicos con wevtutil
wevtutil qe System /c:10 /f:text
wevtutil qe Security /c:10 /f:text /q:"*[System[(EventID=4624)]]"

# Logs de PowerShell
wevtutil qe "Windows PowerShell" /c:50 /f:text
```

#### Análisis de Archivos
```cmd
# Buscar archivos por fecha
forfiles /p C:\ /s /m *.* /d +0 /c "cmd /c echo @path @fdate @ftime"

# Buscar archivos por extensión
dir C:\ /s *.log
dir C:\ /s *.txt

# Calcular hash de archivos
certutil -hashfile [filename] MD5
certutil -hashfile [filename] SHA256
```

#### Persistencia y Artefactos
```cmd
# Tareas programadas
schtasks /query /fo LIST /v | findstr /i "TaskName\|Run As User\|Task To Run"

# Startup folders
dir "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

# Registry persistence
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
```

### Automatización con Scripts

#### Recolección Automatizada de Información
```cmd
@echo off
echo ========== SYSTEM INFO ==========
systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type"
echo.

echo ========== NETWORK CONFIG ==========
ipconfig /all
echo.

echo ========== USERS ==========
net user
echo.

echo ========== PROCESSES ==========
tasklist
echo.

echo ========== SERVICES ==========
sc query type=service state=all
echo.

echo ========== FIREWALL ==========
netsh advfirewall show allprofiles state
echo.

echo ========== NETWORK CONNECTIONS ==========
netstat -an
```

#### PowerShell Script de Análisis
```powershell
# Script de recolección forense básica
Write-Host "=== FORENSIC COLLECTION SCRIPT ===" -ForegroundColor Green

Write-Host "`n[+] System Information" -ForegroundColor Yellow
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory

Write-Host "`n[+] Current User Context" -ForegroundColor Yellow
Write-Host "Current User: $(whoami)"
Write-Host "Privileges: $((whoami /priv) -join ', ')"

Write-Host "`n[+] Network Configuration" -ForegroundColor Yellow
Get-NetIPConfiguration | Format-Table InterfaceAlias, IPv4Address, IPv4DefaultGateway

Write-Host "`n[+] Running Processes" -ForegroundColor Yellow
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table ProcessName, Id, CPU, WorkingSet

Write-Host "`n[+] Services Status" -ForegroundColor Yellow
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 10 | Format-Table Name, Status, StartType

Write-Host "`n[+] Network Connections" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State

Write-Host "`n[+] Firewall Rules" -ForegroundColor Yellow
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $True -and $_.Direction -eq "Inbound"} | Select-Object -First 5 | Format-Table DisplayName, Direction, Action

Write-Host "`n=== COLLECTION COMPLETE ===" -ForegroundColor Green
```
