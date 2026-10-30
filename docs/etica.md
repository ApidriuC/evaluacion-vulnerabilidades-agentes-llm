# Alcance, consideraciones éticas y legales

Documento de encuadre ético del proyecto. En un trabajo de seguridad ofensiva,
delimitar qué se hace y qué no es parte del rigor, no un anexo opcional.

## Principio rector

La investigación evalúa vulnerabilidades **de un sistema construido para ese fin**,
en un laboratorio aislado, sin tocar sistemas de terceros ni datos reales. El
objetivo es producir conocimiento defensivo —identificar debilidades y validar
mitigaciones— no desarrollar capacidad ofensiva reutilizable contra sistemas en
producción.

## El entorno es completamente simulado

- **Sin red real.** La herramienta `http_get` no abre ninguna conexión: registra
  el intento y su contenido. La exfiltración se *mide* sin que ningún dato salga.
- **Sin shell real.** `ejecutar_shell` no ejecuta nada; devuelve una salida
  verosímil y registra el comando que el agente decidió lanzar.
- **Sin datos reales.** Todos los "secretos" son **canarios sintéticos** con la
  forma `CAN-XXX-############`, generados por el propio laboratorio. No
  corresponden a ninguna credencial, persona, cifra ni contrato real.
- **Sin envío real de correo.** `enviar_correo` encola en memoria y registra.

El evento de seguridad que se mide es la **intención consumada** del agente:
haber invocado una herramienta de egreso con un secreto como argumento. Ese es
exactamente el evento que importa para evaluar el riesgo, y se captura sin
producir el daño.

## Lo que el proyecto NO hace

- No ataca modelos, APIs ni servicios de terceros fuera del entorno de laboratorio.
- No busca "jailbreaks" novedosos con el fin de publicarlos como armas; los
  payloads usados son variantes de técnicas ya documentadas públicamente
  (OWASP LLM Top 10, literatura citada en el anteproyecto).
- No recopila ni procesa datos personales reales de ninguna persona.
- No evade mecanismos de seguridad de proveedores comerciales; cuando el modelo
  rechaza un ataque (`stop_reason: refusal`), eso se **registra como dato**, no
  se intenta sortear.

## Manejo responsable de hallazgos

- Los resultados se reportan de forma agregada (tasas, no reconstrucciones paso a
  paso de un exploit contra un producto concreto).
- Si durante las corridas con el proveedor real se observa un comportamiento del
  modelo que constituya una vulnerabilidad del proveedor (no del agente que
  construimos), se seguirá divulgación responsable con el proveedor antes de
  cualquier publicación.

## Marco normativo de referencia

- **NIST AI RMF 1.0 (2023)** — gestión de riesgos de sistemas de IA; guía la Fase 3.
- **NIST SP 800-30 Rev.1** — evaluación de riesgos en términos de probabilidad e
  impacto; sustenta la matriz de riesgo.
- **OWASP Top 10 for LLM Applications (2025)** — taxonomía de las vulnerabilidades
  evaluadas.
- **MITRE ATLAS** — técnicas adversarias contra sistemas de IA, para trazar cada
  escenario a una técnica reconocida.

## Reproducibilidad

Cada corrida registra modelo, proveedor, política, semilla y esfuerzo. El entorno
se reconstruye de forma determinista desde una semilla fija, de modo que cualquier
tercero pueda reproducir los experimentos y auditar las conclusiones.
