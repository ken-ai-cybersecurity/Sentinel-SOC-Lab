# Sentinel-SOC-Lab
Network Engineer transitioning into Cybersecurity Analyst | SOC &amp; Threat Detection Enthusiast.
# Microsoft Sentinel SOC Lab  

## 📌 Project Overview  
This project demonstrates how I set up a **SOC lab using Microsoft Sentinel** to detect and analyze common attack techniques.  
I simulated brute-force logins, suspicious PowerShell execution, and impossible travel logins, then used **KQL queries** to detect them.  

---

## 🏗️ Lab Setup  
- **Platform:** Microsoft Azure  
- **Tools:** Microsoft Sentinel, Log Analytics Workspace  
- **Data Sources Connected:**  
  - Windows 10 Security Events (via Azure Monitor Agent)  
  - Azure Active Directory Sign-in Logs  
- **Diagram:**  
![Architecture](docs/lab-architecture.png)  

---

## 🎯 Attack Scenarios  

### 1️⃣ Brute-force Login Attempts  
- **Simulation:** Multiple failed RDP logins.  
- **Detection Query:** [brute_force.kql](queries/brute_force.kql)  
- **Result Screenshot:**  
![Brute Force Alert](screenshots/brute_force_alert.png)  

---

### 2️⃣ Suspicious PowerShell Execution  
- **Simulation:** Running `powershell -nop -enc <base64payload>`  
- **Detection Query:** [powershell_suspicious.kql](queries/powershell_suspicious.kql)  
- **Result Screenshot:**  
![PowerShell Alert](screenshots/powershell_alert.png)  

---

### 3️⃣ Impossible Travel (Azure AD Logins)  
- **Simulation:** Logins from two distant geolocations within minutes.  
- **Detection Query:** [impossible_travel.kql](queries/impossible_travel.kql)  
- **Result Screenshot:**  
![Impossible Travel](screenshots/impossible_travel.png)  

---

## 🔍 Detection Queries (Samples)  

**Brute-force detection:**  
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by TargetUserName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
