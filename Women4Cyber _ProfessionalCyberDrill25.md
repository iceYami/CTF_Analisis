# Women4Cyber 2025 Professional CyberDrill
## Manual de Preparación Personal

**Objetivo**: Preparación sistemática para competir al máximo nivel en el evento más prestigioso de mujeres en ciberseguridad.

---

## INFORMACIÓN CRÍTICA DEL EVENTO

### Especificaciones Oficiales
- **Fecha**: 6 Septiembre 2025 | 15:00-20:30 CEST
- **Pre-Drill Session**: 29 Agosto 2025 | 15:00 CEST (OBLIGATORIO)
- **Modalidad**: Online, equipos asignados por organización
- **Duración**: 4,5 horas de competición efectiva
- **Plataforma**: app.cyberranges.com
- **Idioma**: Inglés
- **Contacto**: w4c-contact@cyberranges.com

### Timeline Oficial
```
15:00-15:30    Conexión participantes
15:30-15:45    Bienvenida W4C Foundation
15:45-16:00    Briefing técnico CYBER RANGES
16:00-20:00    COMPETICIÓN PRINCIPAL
20:00-20:30    Clausura y despedida
```

### Sistema de Puntuación
- Puntuación específica por pregunta
- Número limitado de intentos por ejercicio
- Cálculo de competency percentage
- Medición de accuracy (intentos utilizados)
- Mapeo completo al NIST NICE Framework

### Premios
- **1º**: Viaje W4C Conference (2 personas) + CITADEL Red Team Elite Training + Gold Certificate
- **2º**: Reconocimiento W4C + Silver Certificate  
- **3º**: Reconocimiento W4C + Bronze Certificate
- **Todos**: Certificate of Participation

---

## ANÁLISIS DE CONOCIMIENTOS REQUERIDOS

### Conocimientos OBLIGATORIOS (según convocatoria oficial)

#### 1. Fundamentos de Respuesta a Incidentes
- **Marco NIST**: Identificación → Contención → Erradicación → Recuperación → Lecciones aprendidas
- **Playbooks estándar**: Procedimientos documentados por tipo de incidente
- **Chain of custody**: Preservación de evidencia digital
- **Escalación**: Protocolos internos y externos

#### 2. Análisis de Logs con SIEM
- **ELK Stack**: Elasticsearch queries, Kibana dashboards, Logstash processing
- **Wazuh**: Rule-based detection, correlation engines
- **Splunk concepts**: SPL basics, search optimization
- **Log correlation**: Event timeline reconstruction

#### 3. Análisis de Tráfico de Red
- **Arkime**: Session-based analysis, query syntax
- **Wireshark**: Protocol analysis, display filters, stream following
- **TCPdump**: Command-line packet capture
- **Network anomaly detection**: Baseline vs. suspicious patterns

#### 4. Tipos Comunes de Ciberataques
- **Phishing**: Email analysis, domain reputation, attachment inspection
- **Malware**: Behavioral analysis, C&C detection, process monitoring
- **Ransomware**: Encryption patterns, recovery procedures
- **DDoS**: Traffic volume analysis, mitigation strategies
- **Lateral movement**: Authentication anomalies, privilege escalation

### Conocimientos DESEABLES

#### 1. Análisis Intermedio de Malware
- **Análisis estático**: Strings, metadata, hash analysis
- **Análisis dinámico**: Sandbox execution, behavioral monitoring
- **IOC extraction**: Indicators of Compromise documentation

#### 2. Técnicas Avanzadas de Detección
- **Threat Hunting**: Hypothesis-driven investigation
- **Behavioral Analysis**: UEBA concepts
- **Threat Intelligence**: IOC integration, TTP mapping

---

## PREPARACIÓN TÉCNICA SISTEMÁTICA

### Requisitos de Hardware Verificados
```
Processor:    Intel i5 8th gen / AMD Ryzen 5 (minimum)
Memory:       8GB RAM (16GB recommended)
Storage:      100GB free for log analysis
Display:      1366x768 minimum (1920x1080+ optimal)
```

### Conectividad - Tests Obligatorios
```bash
# Velocidad mínima verificada
Download: >25 Mbps | Upload: >5 Mbps
Latency: <100ms to European servers

# Comando de verificación
ping -c 10 google.com
speedtest-cli

# Backup connection ready
Mobile data plan configured and tested
```

### Configuración de Navegador Optimizada
```javascript
// Chrome/Firefox/Edge configurado
JavaScript: ENABLED
Third-party cookies: ENABLED  
Pop-ups: ALLOWED for *.cyberranges.com
Cache: CLEARED before event
Extensions: DISABLED (non-essential)
```

### Software de Apoyo Instalado
- **Editor avanzado**: VS Code con JSON/YAML extensions
- **Terminal**: Windows Terminal / iTerm2 
- **Calculator**: Scientific mode para análisis numérico
- **Screenshots**: Greenshot configurado
- **Timer**: Pomodoro app para gestión de tiempo

---

## KNOWLEDGE BASE TÉCNICO

### ELK Stack - Query Reference
```json
# Búsquedas IP específica
source.ip: "192.168.1.100" OR destination.ip: "10.0.0.5"

# Filtros temporales precisos  
@timestamp:[2025-09-06T15:00:00 TO 2025-09-06T20:30:00]

# Eventos críticos de seguridad
event.severity: "high" AND event.category: ("malware" OR "intrusion_detection")

# Patrones de autenticación fallida
event.category: "authentication" AND event.outcome: "failure"

# Detección de powershell sospechoso
message: (*powershell* AND *-enc*) OR (*cmd.exe* AND *bypass*)

# Agregaciones estadísticas
{
  "aggs": {
    "top_sources": {"terms": {"field": "source.ip", "size": 20}},
    "hourly_events": {
      "date_histogram": {"field": "@timestamp", "calendar_interval": "1h"}
    }
  }
}
```

### Wireshark - Display Filters Operacionales
```bash
# Análisis de segmento de red
ip.addr == 192.168.1.0/24 and not broadcast

# Detección de comunicaciones C&C
dns.qry.name matches ".*\.suspicious\.com" or 
dns.qry.name matches ".*[0-9]{8,}\..*"

# HTTP POST sospechoso con payload
http.request.method == "POST" and http.content_length > 1000

# Port scan detection
tcp.flags.syn == 1 and tcp.flags.ack == 0 and 
tcp.window_size <= 1024

# Data exfiltration patterns
tcp.len > 1460 and tcp.flags.psh == 1 and 
frame.time_delta < 0.1

# TLS certificate analysis
tls.handshake.type == 11 and 
tls.handshake.certificate contains "suspicious"
```

### Attack Pattern Recognition Matrix

| Vector | Network Indicators | Host Indicators | Timeline Markers |
|--------|-------------------|-----------------|------------------|
| **APT** | Low-volume, persistent connections | Living-off-land tools, scheduled tasks | Extended dwell time (weeks/months) |
| **Ransomware** | Discovery scans, file share enumeration | Mass file encryption, shadow copy deletion | Rapid encryption (hours) |
| **Phishing** | DNS queries to suspicious domains | Email client process execution | Initial compromise to payload |
| **Insider** | Off-hours access, unusual data access | Data staging, compression tools | Gradual data accumulation |
| **Supply Chain** | Update mechanisms, trusted processes | Signed malware, process hollowing | Update window exploitation |

---

## PROGRAMA DE ENTRENAMIENTO

### Fase I: Fundamentos (19-25 Agosto)

#### Día 1: Platform Readiness
- [ ] Account creation en app.cyberranges.com completado
- [ ] Email confirmation y profile setup finalizado  
- [ ] Network connectivity tests ejecutados
- [ ] Browser optimization implementada
- [ ] Backup systems configurados y testados

#### Día 2-3: Core Knowledge Acquisition
- [ ] NIST SP 800-61 Rev. 2 estudiado completamente
- [ ] Incident response phases memorizadas
- [ ] Common attack vectors documentados
- [ ] IOC identification techniques practicadas

#### Día 4-5: SIEM Mastery
- [ ] ELK Stack tutorials completados
- [ ] Query syntax dominada
- [ ] Dashboard navigation fluida
- [ ] Wazuh rule analysis practicada

#### Día 6-7: Network Analysis Proficiency  
- [ ] Wireshark filtering mastered
- [ ] Protocol analysis techniques aplicadas
- [ ] Arkime interface navegada
- [ ] Traffic analysis scenarios practicados

### Fase II: Skill Integration (26 Agosto - 1 Septiembre)

#### Día 1-2: Practical Application
- [ ] Real incident case studies analizados
- [ ] Multi-tool correlation exercises ejecutados  
- [ ] Evidence documentation practicada
- [ ] Timeline reconstruction completada

#### Día 3-4: Advanced Techniques
- [ ] MITRE ATT&CK mapping aplicado
- [ ] Threat hunting methodology estudiada
- [ ] Behavioral analysis concepts integrados
- [ ] Advanced correlation techniques dominadas

#### Día 5-7: Performance Optimization
- [ ] Speed drills ejecutados
- [ ] Accuracy benchmarks establecidos
- [ ] Stress testing completado
- [ ] Methodology refinement finalizado

### Fase III: Final Preparation (2-6 Septiembre)

#### Pre-Drill Session (29 Agosto - CRÍTICO)
- [ ] **ASISTENCIA OBLIGATORIA CONFIRMADA**
- [ ] Platform functionality verified
- [ ] Team assignment acknowledged
- [ ] Technical issues resolved
- [ ] Interface familiarity achieved

#### Final Countdown (2-5 Septiembre)
- [ ] Knowledge maintenance (light review only)
- [ ] Physical workspace prepared
- [ ] Mental preparation techniques applied
- [ ] Rest and nutrition optimized
- [ ] Equipment final checks completed

---

## OPERATIONAL PROCEDURES - DÍA DEL EVENTO

### Pre-Mission Checklist (06:00-14:45)

#### Physical Preparation
- [ ] **06:00** Natural wake-up, no stress alarms
- [ ] **07:00** Balanced breakfast, optimal nutrition
- [ ] **08:00** Light physical exercise (20 minutes)
- [ ] **09:00** Mindfulness session (15 minutes)
- [ ] **10:00** Light knowledge review (30 minutes MAX)

#### Technical Setup
- [ ] **12:00** Workspace configuration completed
- [ ] **13:00** Final connectivity verification
- [ ] **13:30** Platform access confirmed
- [ ] **14:00** Support materials organized
- [ ] **14:30** System status green across all components
- [ ] **14:45** Mental preparation and focus state achieved

### Mission Execution (15:00-20:30)

#### Phase 1: Connection & Orientation (15:00-16:00)
- **15:00** Immediate lobby connection established
- **15:02** Identity confirmed in general chat
- **15:05** Team assignment verified and acknowledged
- **15:30** W4C welcome presentation (active listening)
- **15:45** CYBER RANGES briefing (detailed notes)
- **16:00** Competition start - full operational mode

#### Phase 2: Tactical Execution (16:00-20:00)

**Hour 1 (16:00-17:00): Establish Momentum**
- Initial challenge analysis (thorough read)
- Methodology application (systematic approach)  
- First successful submission (quality verified)
- Team coordination protocols established

**Hour 2-3 (17:00-19:00): Peak Performance**
- Complex challenge engagement
- Advanced tool utilization
- Multi-source evidence correlation
- High-value target completion

**Hour 4 (19:00-20:00): Final Push**
- Outstanding challenges prioritized
- Quality assurance on all submissions
- Final optimization opportunities
- Competition closure preparation

#### Phase 3: Debrief (20:00-20:30)
- Mission completion acknowledged
- Performance self-assessment
- Networking opportunities maximized
- Professional connections established

---

## TACTICAL ANALYSIS METHODOLOGY

### Incident Analysis Protocol

#### Step 1: Situation Assessment (5-10 minutes)
1. **Complete scenario read-through** - understand full context
2. **Asset identification** - determine affected systems
3. **Timeline establishment** - preliminary event sequence
4. **Evidence source prioritization** - most critical data first

#### Step 2: Evidence Collection (15-25 minutes)
1. **System logs extraction** - relevant timeframe focus
2. **Network traffic capture** - suspicious pattern identification  
3. **Host artifacts gathering** - process, file, registry evidence
4. **Temporal correlation** - event synchronization across sources

#### Step 3: Analysis & Correlation (10-20 minutes)
1. **Pattern matching** - known TTP comparison
2. **IOC validation** - indicator verification and expansion
3. **Attack chain reconstruction** - complete kill chain mapping
4. **Impact assessment** - damage scope and severity

#### Step 4: Documentation & Response (5-10 minutes)
1. **Evidence summary** - clear, concise findings
2. **Technical conclusions** - data-driven determinations
3. **Mitigation recommendations** - actionable next steps
4. **Quality verification** - accuracy check before submission

### Performance Optimization Techniques

#### Cognitive Load Management
- **Time boxing**: Maximum 45 minutes per complex challenge
- **Priority matrix**: High-value targets first
- **Buffer allocation**: 15% time reserve for reviews

#### Stress Mitigation
- **Controlled breathing**: 4-7-8 technique between challenges
- **Positive reinforcement**: Progress acknowledgment
- **Focus anchoring**: Return to proven methodology

#### Physical Optimization  
- **Hydration protocol**: Water every 30 minutes
- **Micro-recovery**: 2-minute breaks hourly
- **Nutrition timing**: Light, sustained energy sources

---

## CONTINGENCY PROCEDURES

### Technical Failure Response

#### Network Connectivity Issues
```bash
# Primary diagnostics
ipconfig /flushdns
nslookup cyberranges.com
tracert cyberranges.com

# Backup activation  
Mobile hotspot deployment
VPN services disabled
Alternative browser ready
```

#### Platform Access Problems
- **Immediate contact**: w4c-contact@cyberranges.com
- **Backup account**: Secondary email ready if needed
- **Alternative device**: Tablet/phone for emergency access
- **Documentation**: Screenshot all error messages

#### Browser Performance Degradation
- **Cache clearing**: Immediate temp file cleanup
- **Process restart**: Complete browser restart
- **Resource monitoring**: Task manager observation
- **Fallback browser**: Secondary option ready

### Operational Backup Plans
- **Internet**: Mobile data plan tested and ready
- **Power**: UPS/battery backup for critical period
- **Communication**: Multiple channels for team contact
- **Documentation**: Physical backup of all cheat sheets

---

## SUCCESS METRICS & POST-EVENT ANALYSIS

### Performance Indicators
- **Completion Rate**: Percentage of attempted challenges
- **Accuracy Score**: First-attempt success rate
- **Time Efficiency**: Average time per challenge type
- **Quality Index**: Depth of analysis demonstrated

### Post-Competition Protocol
- [ ] Immediate performance review
- [ ] Knowledge gap identification  
- [ ] Methodology effectiveness assessment
- [ ] Professional network expansion documentation
- [ ] Continuous improvement plan development

---

## FINAL VERIFICATION CHECKLIST

### Technical Readiness
- [ ] Hardware specifications confirmed adequate
- [ ] Network connectivity tested and verified
- [ ] Platform access working flawlessly
- [ ] Backup systems operational
- [ ] Workspace ergonomically optimized

### Knowledge Readiness  
- [ ] NIST framework internalized
- [ ] SIEM tools mastered
- [ ] Network analysis proficient
- [ ] Attack patterns recognized
- [ ] Analysis methodology solid

### Physical/Mental Readiness
- [ ] Sleep schedule optimized
- [ ] Nutrition plan implemented  
- [ ] Stress management techniques ready
- [ ] Focus and concentration sharp
- [ ] Confidence level high

---

**Mission Brief**: Esta preparación representa mi compromiso personal con la excelencia técnica y la representación profesional de las mujeres en ciberseguridad.

---
