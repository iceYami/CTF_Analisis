# INFORME COMPLETO DE RECONOCIMIENTO TELNET
## Penetration Testing y Análisis de Vulnerabilidades

---

### INFORMACIÓN GENERAL DEL PROYECTO

**IDENTIFICACIÓN DE MISIÓN**
- **Nombre del Proyecto:** Telnet Reconnaissance & Exploitation
- **Nivel de Complejidad:** Básico/Intermedio
- **Target IP:** 172.20.4.28
- **Puerto Objetivo:** 23 (Telnet)

**ALCANCE Y LIMITACIONES**
- Reconocimiento pasivo y activo del target
- Identificación de servicios y versiones
- Enumeración de usuarios y privilegios
- Análisis de archivos y configuraciones
- Documentación completa de hallazgos
- **Limitación:** No modificación de archivos críticos del sistema

---

### FASE 1: RECONOCIMIENTO INICIAL Y CONECTIVIDAD

#### 1.1 VERIFICACIÓN DE CONECTIVIDAD
**Objetivo:** Confirmar disponibilidad y accesibilidad del objetivo

**Comando Principal:**
```bash
ping -c 4 172.20.4.28
```

**Comandos Alternativos:**
```bash
ping -c 10 -i 0.5 172.20.4.28    # Ping extendido con intervalo reducido
ping -c 4 -W 3 172.20.4.28       # Timeout de 3 segundos
fping 172.20.4.28                # Ping rápido alternativo
```

**Resultados Esperados:**
- 0% pérdida de paquetes = Conectividad óptima
- RTT < 50ms = Latencia aceptable
- TTL value indicará tipo de OS (Linux ~64, Windows ~128)

**Análisis de Contingencias:**
- **Pérdida parcial (1-25%):** Posible congestión de red o filtrado
- **Pérdida alta (25-75%):** Firewall o IDS/IPS activo
- **Pérdida total (100%):** Host inaccesible, IP incorrecta o firewall estricto

#### 1.2 DESCUBRIMIENTO DE PUERTOS Y SERVICIOS

**Escaneo Rápido de Puerto Específico:**
```bash
nc -vz 172.20.4.28 23             # Netcat verificación rápida
nc -w 3 -z 172.20.4.28 23         # Con timeout de 3 segundos
```

**Escaneo Detallado con Nmap:**
```bash
nmap -p 23 172.20.4.28                    # Escaneo puerto específico
nmap -sV -p 23 172.20.4.28               # Detección de versión
nmap -sC -sV -p 23 172.20.4.28           # Scripts por defecto + versión
nmap -A -p 23 172.20.4.28                # Escaneo agresivo
```

**Escaneos Complementarios:**
```bash
nmap -sS -p 1-1000 172.20.4.28           # TCP SYN scan puertos comunes
nmap -sU --top-ports 100 172.20.4.28     # UDP scan puertos populares
nmap -sV --version-all 172.20.4.28       # Detección exhaustiva de versiones
nmap -O 172.20.4.28                      # OS fingerprinting
```

**Banner Grabbing Avanzado:**
```bash
nc 172.20.4.28 23                        # Conexión manual para banner
telnet 172.20.4.28 23                    # Conexión Telnet directa
timeout 10s bash -c 'echo "" | nc 172.20.4.28 23'  # Banner automático
```

**Resultado Confirmado:**
- **Puerto:** 23/tcp ABIERTO
- **Servicio:** Telnet
- **Banner Recibido:** `"Hey you, you're trying to connect to me. You should always try default credentials like root:root it's just beginning _ arrow login:"`

---

### FASE 2: ANÁLISIS DE CREDENCIALES Y ACCESO

#### 2.1 ESTRATEGIA DE CREDENCIALES

**Credenciales Primarias (Indicadas por Banner):**
- Usuario: `root`
- Contraseña: `root`

**Diccionario de Credenciales por Defecto:**
```
root:root
admin:admin
administrator:administrator
guest:guest
user:user
test:test
demo:demo
telnet:telnet
admin:password
root:toor
admin:123456
guest:
admin:
root:
```

**Comando de Conexión:**
```bash
telnet 172.20.4.28 23
```

**Automatización de Login (Si es necesario):**
```bash
expect -c "
spawn telnet 172.20.4.28 23
expect \"login:\"
send \"root\r\"
expect \"Password:\"
send \"root\r\"
interact
"
```

#### 2.2 PROCESO DE AUTENTICACIÓN

**Pasos de Conexión:**
1. Ejecutar: `telnet 172.20.4.28 23`
2. Esperar prompt: `login:`
3. Ingresar: `root`
4. Esperar prompt: `Password:`
5. Ingresar: `root`
6. Confirmar acceso exitoso

**Indicadores de Acceso Exitoso:**
- Prompt de shell: `#` (root) o `$` (user)
- Mensaje de bienvenida del sistema
- Capacidad de ejecutar comandos

---

### FASE 3: RECONOCIMIENTO POST-ACCESO

#### 3.1 ORIENTACIÓN INICIAL DEL ENTORNO

**Comandos de Orientación Básica:**
```bash
whoami                    # Usuario actual
id                        # UID, GID y grupos
pwd                       # Directorio actual
hostname                  # Nombre del host
date                      # Fecha y hora del sistema
uptime                    # Tiempo activo y carga
```

**Información del Sistema Operativo:**
```bash
uname -a                  # Kernel completo
cat /etc/os-release       # Distribución y versión
cat /etc/issue            # Banner del sistema
cat /proc/version         # Versión del kernel detallada
lsb_release -a            # Información LSB (si disponible)
```

#### 3.2 ENUMERACIÓN DE USUARIOS Y PRIVILEGIOS

**Análisis de Usuarios:**
```bash
cat /etc/passwd                           # Todos los usuarios
cat /etc/passwd | grep -E ":/bin/(bash|sh|zsh|fish)"  # Usuarios con shell
cat /etc/group                            # Grupos del sistema
getent passwd                             # Usuarios via NSS
who                                       # Usuarios conectados
last                                      # Historial de conexiones
```

**Análisis de Privilegios:**
```bash
sudo -l                                   # Permisos sudo (si disponible)
cat /etc/sudoers 2>/dev/null              # Configuración sudoers
find / -perm -4000 2>/dev/null            # Binarios SUID
find / -perm -2000 2>/dev/null            # Binarios SGID
getcap -r / 2>/dev/null                   # Capabilities
```

#### 3.3 EXPLORACIÓN DEL SISTEMA DE ARCHIVOS

**Directorio de Trabajo Inicial (/root):**
```bash
ls -la /root                              # Contenido detallado
ls -la /root/.??*                         # Archivos ocultos específicos
find /root -type f -name ".*" 2>/dev/null # Archivos ocultos recursivo
```

**Búsqueda de Archivos de Interés:**
```bash
# Archivos de texto y documentos
find / -name "*.txt" -type f 2>/dev/null
find / -name "*.doc*" -type f 2>/dev/null
find / -name "*.pdf" -type f 2>/dev/null
find / -name "README*" -type f 2>/dev/null

# Archivos de configuración
find / -name "*.conf" -type f 2>/dev/null
find / -name "*.cfg" -type f 2>/dev/null
find / -name "*.ini" -type f 2>/dev/null
find /etc -name "*.conf" -type f 2>/dev/null

# Copias de seguridad y temporales
find / -name "*.bak" -type f 2>/dev/null
find / -name "*.backup" -type f 2>/dev/null
find / -name "*.old" -type f 2>/dev/null
find / -name "*.tmp" -type f 2>/dev/null
```

**Scripts y Ejecutables Interesantes:**
```bash
find / -name "*.sh" -type f 2>/dev/null
find / -name "*.py" -type f 2>/dev/null
find / -name "*.pl" -type f 2>/dev/null
find / -name "*.rb" -type f 2>/dev/null
find / -executable -type f 2>/dev/null | head -20
```

#### 3.4 ANÁLISIS DE PROCESOS Y SERVICIOS

**Procesos Activos:**
```bash
ps aux                                    # Todos los procesos
ps -ef                                    # Formato alternativo
ps auxww                                  # Sin truncar líneas
top -n 1                                  # Vista instantánea de procesos
htop                                      # Si está disponible
pstree                                    # Árbol de procesos
```

**Servicios y Puertos:**
```bash
netstat -tulnp                            # Puertos TCP/UDP con PID
ss -tulnp                                 # Sustituto moderno de netstat
lsof -i                                   # Archivos/sockets de red abiertos
lsof -i :23                               # Específico puerto 23
netstat -rn                               # Tabla de ruteo
arp -a                                    # Tabla ARP
```

**Servicios del Sistema:**
```bash
service --status-all                      # Estado de servicios (SysV)
systemctl list-units --type=service      # Servicios systemd
systemctl list-units --state=running     # Servicios activos
chkconfig --list 2>/dev/null              # Servicios al inicio
```

---

### FASE 4: ANÁLISIS AVANZADO Y ENUMERACIÓN PROFUNDA

#### 4.1 ANÁLISIS DE LOGS Y ACTIVIDAD

**Logs del Sistema:**
```bash
ls -la /var/log/                          # Directorio de logs
tail -20 /var/log/auth.log 2>/dev/null    # Autenticaciones
tail -20 /var/log/secure 2>/dev/null      # Logs de seguridad
tail -20 /var/log/messages 2>/dev/null    # Mensajes del sistema
tail -20 /var/log/syslog 2>/dev/null      # Log principal
```

**Historial de Comandos:**
```bash
cat ~/.bash_history 2>/dev/null           # Historial bash
cat ~/.history 2>/dev/null                # Historial genérico
history                                   # Historial sesión actual
find /home -name ".*history" 2>/dev/null  # Historiales de usuarios
```

#### 4.2 ANÁLISIS DE RED Y CONECTIVIDAD

**Configuración de Red:**
```bash
ifconfig -a                               # Interfaces de red
ip addr show                              # IP addresses
ip route show                             # Rutas
cat /etc/hosts                            # Hosts locales
cat /etc/resolv.conf                      # DNS
```

**Conexiones Activas:**
```bash
netstat -an | grep ESTABLISHED            # Conexiones establecidas
ss -tuln | grep LISTEN                    # Puertos en escucha
lsof -i -P | grep LISTEN                  # Procesos escuchando
```

#### 4.3 VARIABLES DE ENTORNO Y CONFIGURACIÓN

**Variables del Sistema:**
```bash
env                                       # Variables de entorno
set                                       # Variables shell
echo $PATH                                # PATH del sistema
echo $HOME                                # Directorio home
echo $USER                                # Usuario actual
```

**Archivos de Configuración Críticos:**
```bash
cat /etc/passwd                           # Usuarios
cat /etc/shadow 2>/dev/null               # Passwords hasheadas
cat /etc/group                            # Grupos
cat /etc/fstab                            # Montajes
cat /etc/crontab 2>/dev/null              # Tareas programadas
```

---

### FASE 5: BÚSQUEDA DE FLAGS Y CTF

#### 5.1 PATRONES TÍPICOS DE CTF

**Búsqueda de Flags:**
```bash
find / -name "*flag*" -type f 2>/dev/null
find / -name "*ctf*" -type f 2>/dev/null
find / -name "*key*" -type f 2>/dev/null
grep -r "flag{" / 2>/dev/null | head -10
grep -r "CTF{" / 2>/dev/null | head -10
grep -r "FLAG{" / 2>/dev/null | head -10
```

**Archivos Ocultos y Especiales:**
```bash
find / -name ".*" -type f 2>/dev/null | grep -v proc | head -20
find / -size +0c -size -100c 2>/dev/null  # Archivos pequeños
find / -empty -type f 2>/dev/null          # Archivos vacíos
```

**Codificación y Ofuscación:**
```bash
find / -name "*.b64" 2>/dev/null          # Base64
find / -name "*.enc" 2>/dev/null          # Encriptados
strings /bin/* 2>/dev/null | grep -i flag # Strings en binarios
```

#### 5.2 DIRECTORIOS COMUNES DE CTF

**Ubicaciones Típicas:**
```bash
ls -la /home/*/Desktop/
ls -la /opt/
ls -la /tmp/
ls -la /var/www/
ls -la /usr/local/bin/
cat /root/.bashrc
cat /root/.profile
```

---

### FASE 6: DOCUMENTACIÓN Y REGISTRO

#### 6.1 TEMPLATE DE REGISTRO

**Información a Documentar:**
```
TIMESTAMP: [Fecha y hora de cada comando]
COMANDO: [Comando ejecutado exacto]
OUTPUT: [Salida completa del comando]
OBSERVACIONES: [Notas relevantes]
HALLAZGOS: [Información crítica encontrada]
```

**Script de Documentación Automática:**
```bash
# Crear log automático
exec > >(tee -a recon_log.txt) 2>&1
echo "=== INICIO SESIÓN $(date) ==="
# Ejecutar comandos normalmente, quedarán registrados
```

#### 6.2 CHECKLIST

**Conectividad y Acceso:**
- [ ] Ping exitoso
- [ ] Puerto 23 confirmado abierto
- [ ] Banner capturado completamente
- [ ] Acceso con root:root exitoso
- [ ] Shell interactivo funcional

**Reconocimiento del Sistema:**
- [ ] Información del OS documentada
- [ ] Usuarios identificados
- [ ] Privilegios confirmados
- [ ] Directorio inicial explorado
- [ ] Procesos activos listados

**Búsqueda de Información:**
- [ ] Archivos .txt encontrados
- [ ] Archivos .conf revisados
- [ ] Archivos .bak verificados
- [ ] Logs del sistema revisados
- [ ] Variables de entorno documentadas

**CTF y Flags:**
- [ ] Búsqueda de flags ejecutada
- [ ] Archivos ocultos explorados
- [ ] Directorios comunes verificados
- [ ] Strings en binarios revisados

---

### FASE 7: ANÁLISIS DE RIESGOS

#### 7.1 VULNERABILIDADES IDENTIFICADAS

**Riesgos Críticos:**
1. **Protocolo sin cifrado:** Telnet transmite credenciales en texto plano
2. **Credenciales por defecto:** root:root es extremadamente inseguro
3. **Acceso root directo:** Sin escalación de privilegios necesaria
4. **Banner informativo:** Revela información innecesaria

**Impacto de Seguridad:**
- Compromiso total del sistema
- Acceso a todos los archivos y configuraciones
- Capacidad de modificar el sistema
- Intercepción de credenciales en red

#### 7.2 RECOMENDACIONES DE SEGURIDAD

**Inmediatas:**
1. Deshabilitar servicio Telnet
2. Implementar SSH en su lugar
3. Cambiar credenciales por defecto
4. Configurar autenticación por clave pública

**A Mediano Plazo:**
1. Implementar fail2ban para intentos de fuerza bruta
2. Configurar firewall restrictivo
3. Auditoría de usuarios y privilegios
4. Monitoreo de logs de seguridad

**Mejores Prácticas:**
1. Principio de menor privilegio
2. Autenticación multifactor
3. Segmentación de red
4. Actualizaciones regulares de seguridad

---

### FASE 8: COMANDOS DE REFERENCIA RÁPIDA

#### 8.1 COMANDOS ESENCIALES

**Reconocimiento Inicial:**
```bash
ping -c 4 172.20.4.28
nc -vz 172.20.4.28 23
nmap -sV -p 23 172.20.4.28
telnet 172.20.4.28 23
```

**Post-Acceso Inmediato:**
```bash
whoami && id && pwd
uname -a
cat /etc/os-release
ls -la
```

**Enumeración Rápida:**
```bash
cat /etc/passwd
ps aux
netstat -tulnp
find / -name "*.txt" 2>/dev/null | head -10
```

#### 8.2 ONE-LINERS ÚTILES

**Recopilación Rápida de Información:**
```bash
echo "=== SYSTEM INFO ===" && uname -a && echo "=== USERS ===" && cat /etc/passwd && echo "=== NETWORK ===" && netstat -tulnp
```

**Búsqueda de Flags CTF:**
```bash
find / \( -name "*flag*" -o -name "*ctf*" -o -name "*key*" \) 2>/dev/null
```

**Procesos y Red Combinados:**
```bash
ps aux && echo "=== NETWORK ===" && netstat -tulnp && echo "=== LISTENING ===" && ss -tulnp
```

---

### ANEXOS

#### ANEXO A: CÓDIGOS DE ERROR COMUNES

**Conectividad:**
- `Network is unreachable`: Problema de enrutamiento
- `Connection refused`: Puerto cerrado o servicio inactivo
- `Connection timed out`: Firewall o filtrado

**Telnet:**
- `Login incorrect`: Credenciales incorrectas
- `Permission denied`: Restricciones de acceso
- `Connection closed by foreign host`: Servicio rechaza conexión

#### ANEXO B: HERRAMIENTAS ALTERNATIVAS

**Si nc no está disponible:**
```bash
timeout 5 bash -c '</dev/tcp/172.20.4.28/23'  # Test de conexión con bash
```

**Si nmap no está disponible:**
```bash
for port in 21 22 23 80 443; do timeout 1 bash -c "</dev/tcp/172.20.4.28/$port" && echo "Port $port open"; done
```

#### ANEXO C: AUTOMATIZACIÓN

**Script de Reconocimiento Completo:**
```bash
#!/bin/bash
TARGET="172.20.4.28"
echo "=== Starting recon for $TARGET ==="
ping -c 2 $TARGET
nmap -sV -p 23 $TARGET
echo "Attempting telnet connection..."
# Aquí continuaría la automatización
```

---

### CONCLUSIONES

**Resumen Ejecutivo:**
El target 172.20.4.28 presenta múltiples vulnerabilidades críticas que permiten acceso completo al sistema mediante credenciales por defecto a través del protocolo Telnet no cifrado. El sistema aparenta ser un entorno de laboratorio o CTF basado en el banner informativo recibido.

**Hallazgos Principales:**
- Servicio Telnet activo en puerto 23
- Credenciales por defecto root:root funcionales
- Acceso root completo al sistema
- Entorno probablemente destinado a práctica/CTF

**Próximas Acciones Recomendadas:**
1. Completar enumeración exhaustiva
2. Documentar todos los hallazgos
3. Buscar flags o objetivos específicos del CTF
4. Mantener registro detallado para reporte final

---

**NOTA FINAL:** Este informe está diseñado para entornos de laboratorio y CTF. En entornos de producción, siempre seguir protocolos de ethical hacking y contar con autorización explícita antes de realizar cualquier actividad de penetration testing.
