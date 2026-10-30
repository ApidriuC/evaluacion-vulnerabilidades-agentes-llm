#!/usr/bin/env python
"""Interfaz de línea de comandos del laboratorio.

    python cli.py listar
    python cli.py verificar
    python cli.py ejecutar --politica C0 --politica C4 --repeticiones 30
    python cli.py metricas --csv resultados/tabla.csv
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
sys.path.insert(0, str(RAIZ / "src"))

from lab import escenarios as mod_escenarios  # noqa: E402
from lab import metricas as mod_metricas  # noqa: E402
from lab import runner  # noqa: E402
from lab.config import CONFIGURACIONES, ConfigCorrida  # noqa: E402

DIR_ESCENARIOS = RAIZ / "escenarios"
DIR_RESULTADOS = RAIZ / "resultados"


def cmd_listar(args) -> int:
    escs = mod_escenarios.cargar_directorio(Path(args.escenarios))
    print(f"\n{len(escs)} escenarios en {args.escenarios}\n")
    print(f"{'ID':<12} {'Tipo':<9} {'OWASP':<8} {'Canal':<12} Nombre")
    print("-" * 92)
    for e in escs:
        print(f"{e.id:<12} {e.tipo:<9} {e.categoria_owasp:<8} {e.canal:<12} {e.nombre}")
    ataques = sum(1 for e in escs if e.tipo == "ataque")
    print(f"\n{ataques} de ataque, {len(escs) - ataques} de utilidad.\n")
    return 0


def cmd_verificar(args) -> int:
    """Prueba de humo del arnés con el proveedor simulado (sin red ni coste).

    Comprueba que la instrumentación funciona: bajo C0 los ataques deben tener
    éxito y bajo C4 deben caer. Si no ocurre, el problema está en el arnés.
    """
    escs = mod_escenarios.cargar_directorio(Path(args.escenarios))
    salida = DIR_RESULTADOS / f"verificacion-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    print("Verificando el arnés con el proveedor simulado (sin llamadas a la API)...\n")
    for nombre in ("C0", "C4"):
        config = ConfigCorrida(
            politica=CONFIGURACIONES[nombre], proveedor="simulado", repeticiones=args.repeticiones
        )
        runner.ejecutar_campana(escs, config, salida)

    registros = mod_metricas.cargar([salida])
    celdas = mod_metricas.agregar(registros)
    resumen = mod_metricas.resumen_por_politica(celdas)
    print(mod_metricas.render_resumen(resumen))

    base = next((f for f in resumen if f["politica"] == "C0"), None)
    duro = next((f for f in resumen if f["politica"] == "C4"), None)
    if base and duro and base["asr"] > duro["asr"]:
        print("\nArnés OK: el ASR cae al endurecer la política.\n")
        return 0
    print("\nRevisar el arnés: el endurecimiento no redujo el ASR simulado.\n")
    return 1


def cmd_ejecutar(args) -> int:
    escs = mod_escenarios.cargar_directorio(Path(args.escenarios))
    if args.solo:
        escs = [e for e in escs if e.id in set(args.solo)]
        if not escs:
            print(f"Ningún escenario coincide con {args.solo}", file=sys.stderr)
            return 2

    marca = time.strftime("%Y%m%d-%H%M%S")
    salida = Path(args.salida) if args.salida else DIR_RESULTADOS / f"campana-{marca}.jsonl"

    total = len(escs) * len(args.politica) * args.repeticiones
    print(f"\nCampaña: {len(escs)} escenarios x {len(args.politica)} políticas x {args.repeticiones} repeticiones")
    print(f"= {total} corridas | proveedor={args.proveedor} modelo={args.modelo or '(por defecto)'}")
    print(f"Salida: {salida}\n")

    for nombre in args.politica:
        if nombre not in CONFIGURACIONES:
            print(f"Política desconocida: {nombre}. Disponibles: {', '.join(CONFIGURACIONES)}", file=sys.stderr)
            return 2
        config = ConfigCorrida(
            politica=CONFIGURACIONES[nombre],
            repeticiones=args.repeticiones,
            proveedor=args.proveedor,
        )
        if args.modelo:
            config.modelo = args.modelo
        if args.effort:
            config.effort = args.effort
        runner.ejecutar_campana(escs, config, salida)

    print(f"\nListo. Analiza con:\n  python cli.py metricas --entrada {salida}\n")
    return 0


def cmd_metricas(args) -> int:
    entrada = Path(args.entrada) if args.entrada else DIR_RESULTADOS
    rutas = [entrada] if entrada.is_file() else sorted(entrada.glob("*.jsonl"))
    if not rutas:
        print(f"No hay archivos .jsonl en {entrada}", file=sys.stderr)
        return 2

    registros = mod_metricas.cargar(rutas)
    simuladas = sum(1 for r in registros if r.get("simulado"))
    celdas = mod_metricas.agregar(registros)

    print(f"\n{len(registros)} corridas leídas de {len(rutas)} archivo(s).")
    if simuladas:
        print(
            f"AVISO: {simuladas} corridas usan el proveedor simulado. "
            "No son resultados experimentales; filtra el archivo antes de reportar."
        )

    print(mod_metricas.render_resumen(mod_metricas.resumen_por_politica(celdas)))
    filas = mod_metricas.tabla_comparativa(celdas, base=args.base)
    print(mod_metricas.render_detalle(filas, base=args.base))

    if args.csv:
        destino = mod_metricas.exportar_csv(filas, Path(args.csv))
        print(f"Tabla exportada a {destino}\n")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="cli.py", description="Laboratorio de vulnerabilidades en agentes LLM"
    )
    sub = p.add_subparsers(dest="comando", required=True)

    def comunes(sp):
        sp.add_argument("--escenarios", default=str(DIR_ESCENARIOS), help="Directorio de escenarios YAML")

    sp = sub.add_parser("listar", help="Lista los escenarios definidos")
    comunes(sp)
    sp.set_defaults(func=cmd_listar)

    sp = sub.add_parser("verificar", help="Prueba de humo del arnés, sin API ni coste")
    comunes(sp)
    sp.add_argument("--repeticiones", type=int, default=5)
    sp.set_defaults(func=cmd_verificar)

    sp = sub.add_parser("ejecutar", help="Ejecuta una campaña experimental")
    comunes(sp)
    sp.add_argument("--politica", action="append", default=None, help="Repetible: --politica C0 --politica C4")
    sp.add_argument("--repeticiones", type=int, default=30)
    sp.add_argument("--proveedor", default="anthropic", choices=["anthropic", "ollama", "simulado"])
    sp.add_argument("--modelo", default=None, help="Sobreescribe el modelo del agente víctima")
    sp.add_argument("--effort", default=None, help="low|medium|high|xhigh|max")
    sp.add_argument("--solo", action="append", default=None, help="Repetible: limita a ciertos IDs")
    sp.add_argument("--salida", default=None)
    sp.set_defaults(func=cmd_ejecutar)

    sp = sub.add_parser("metricas", help="Calcula ASR, utilidad y significancia")
    sp.add_argument("--entrada", default=None, help="Archivo .jsonl o directorio")
    sp.add_argument("--base", default="C0", help="Política de referencia para la comparación")
    sp.add_argument("--csv", default=None)
    sp.set_defaults(func=cmd_metricas)

    args = p.parse_args(argv)
    if getattr(args, "politica", None) is None and args.comando == "ejecutar":
        args.politica = ["C0"]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
