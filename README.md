# AgentGuard

AgentGuard es una librería Python de filtrado determinista para agentes basados en LLM.

El objetivo del proyecto es reducir riesgos asociados al uso de agentes que procesan texto externo, documentos, herramientas o respuestas generadas por modelos de lenguaje. Entre los riesgos contemplados se incluyen prompt injection, instrucciones maliciosas en contenido externo, fuga de credenciales o tokens, y respuestas con información sensible.

Este proyecto corresponde al trabajo anual de Habilitación Profesional. El alcance actual es un MVP funcional y demostrable. El alcance actual es un MVP funcional y demostrable. La librería implementa una primera capa determinista de filtrado, pero no pretende garantizar detección completa de ataques ni compatibilidad universal con frameworks de agentes.

## Funcionalidades implementadas

- Motor de reglas basado en expresiones regulares.
- Reglas configurables mediante `rules.json`.
- Carga de configuración desde JSON.
- Filtro de entrada.
- Filtro de salida.
- Gestor de políticas con acciones:
  - `ALLOW`
  - `WARN`
  - `NEUTRALIZE`
  - `BLOCK`
- Neutralizador básico.
- Logger de eventos de seguridad.
- Wrappers genéricos para herramientas de lectura y escritura.
- Tests unitarios con `pytest`.
- Demo básica del núcleo de filtrado.
- Demo de tool wrappers para simular indirect prompt injection.

## Arquitectura general

Flujo principal del núcleo:

```text
Input externo
→ InputFilter
→ RuleEngine
→ PolicyManager
→ Neutralizer, si corresponde
→ contenido permitido, neutralizado o bloqueado
```

Flujo de salida:

```text
Respuesta generada
→ OutputFilter
→ RuleEngine
→ PolicyManager
→ Neutralizer, si corresponde
→ salida permitida, neutralizada o bloqueada
```

Flujo con herramientas protegidas:

```text
Herramienta de lectura
→ AgentGuard valida el contenido leído
→ contenido seguro o mensaje de bloqueo
→ agente

Salida generada
→ AgentGuard valida el contenido a escribir
→ escritura permitida o bloqueada
```

## Tool wrappers

AgentGuard incluye wrappers genéricos para herramientas de lectura y escritura.

La idea es que una aplicación pueda envolver funciones que leen contenido externo antes de que ese contenido llegue al agente.

Ejemplo conceptual:

```python
safe_read = wrap_read_tool(read_external_document, input_filter)
content = safe_read()
```

También puede envolver funciones que escriben o exponen contenido generado:

```python
safe_write = wrap_write_tool(write_response, output_filter)
safe_write(response)
```

El objetivo no es interceptar automáticamente cualquier framework de agentes, sino ofrecer una interfaz simple para proteger herramientas Python usadas por agentes o flujos automatizados.

## Instalación en modo desarrollo

Desde la raíz del proyecto:

```powershell
python -m pip install -e ".[dev]"
```

## Ejecutar tests

```powershell
python -m pytest tests
```

La suite de tests verifica el motor de reglas, carga de configuración, filtros de entrada y salida, políticas, neutralización, logger y wrappers de herramientas.

## Ejecutar demo básica

```powershell
python .\examples\basic_demo.py
```

Esta demo muestra casos simples de:

- entrada segura;
- entrada bloqueada;
- salida segura;
- salida bloqueada;
- neutralización.

## Ejecutar demo de tool wrappers

```powershell
python .\examples\tool_wrapper_demo.py
```

Esta demo compara un flujo vulnerable contra un flujo protegido con AgentGuard.

En el flujo vulnerable, una herramienta lee contenido externo que contiene una instrucción maliciosa.

En el flujo protegido, la herramienta de lectura se envuelve con AgentGuard, por lo que el contenido externo se bloquea o neutraliza antes de llegar al agente.

## Estado actual del MVP

Actualmente el proyecto incluye:

- núcleo de filtrado funcional;
- reglas configurables;
- políticas de decisión;
- neutralización básica;
- logging de eventos de seguridad;
- wrappers genéricos de lectura y escritura;
- tests automatizados;
- demos ejecutables.

## Próximos pasos

- Mejorar la demo de indirect prompt injection usando contenido HTML local.
- Agregar una demo opcional con LLM local mediante Ollama.
- Ampliar reglas y categorías de detección.
- Documentar criterios de severidad.
- Documentar limitaciones del enfoque determinista.
- Evaluar adaptadores específicos para frameworks de agentes en una etapa posterior.

## Fuera del alcance actual

- Compatibilidad universal con frameworks de agentes.
- Benchmark académico completo.
- Evaluación formal de tasa de ataques exitosos.
- Dataset amplio de ataques.
- Intercepción automática de cualquier herramienta en cualquier framework.
- Garantía de detección de todos los ataques posibles.