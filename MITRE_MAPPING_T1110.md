# MITRE_MAPPING - Proyecto Fuerza Bruta (T1110)

- Técnica: T1110 - Brute Force
- Procedimiento reproducido: Uso de `hydra` desde Kali para probar múltiples contraseñas RDP/SSH contra Windows Server (cuenta: test_user).
- Data sources usados:
  - Windows Security Event Log (EventCode 4625, 4624)
  - Splunk Universal Forwarder logs
  - Syslog desde router/firewall
  - (Opcional) Sysmon para proceso/provenance
- Query SPL principal: ver /splunk/queries.txt
- Detección implementada:
  - Regla simple: >=5 EventCode=4625 por cuenta en 1 minuto.
  - Correlación: fallos seguidos de éxito en maxspan 10 minutos.
- Mitigaciones / recomendaciones:
  - Aplicar account lockout policy, MFA, bloqueo de IP en firewall, revisar políticas de contraseñas.
- Notas de ética y seguridad:
  - Todas las pruebas realizadas únicamente en laboratorio aislado. No ejecutar en entornos de producción o redes de terceros.
