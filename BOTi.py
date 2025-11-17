#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
from urllib.parse import urljoin
import random
import time

import requests
from bs4 import BeautifulSoup

NAMES = [
    "Carlos", "María", "Juan", "Ana", "Luis", "Lucía", "Pedro", "Sofía", "Diego", "Valentina",
    "Javier", "Camila", "Andrés", "Paula", "Miguel", "Elena", "Sergio", "Isabel", "Ricardo", "Laura",
]


def fetch_html(url: str, timeout: int = 15, user_agent: str | None = None, verify_tls: bool = True) -> str:
    headers = {
        "User-Agent": user_agent
        or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
    }
    resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_tls)
    resp.raise_for_status()
    resp.encoding = resp.apparent_encoding or resp.encoding
    return resp.text


def fetch_html_session(session: requests.Session, url: str, timeout: int = 15, user_agent: str | None = None, verify_tls: bool = True, allow_error: bool = False) -> str:
    headers = {
        "User-Agent": user_agent
        or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
    }
    resp = session.get(url, headers=headers, timeout=timeout, verify=verify_tls)
    if not allow_error:
        resp.raise_for_status()
    resp.encoding = resp.apparent_encoding or resp.encoding
    return resp.text


def extract_forms(html: str, base_url: str | None = None) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms_info: list[dict] = []

    for idx, form in enumerate(soup.find_all("form"), start=1):
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""
        action_abs = urljoin(base_url, action) if base_url else action

        inputs = []
        for inp in form.find_all("input"):
            inputs.append(
                {
                    "tag": "input",
                    "type": (inp.get("type") or "text").lower(),
                    "name": inp.get("name"),
                    "id": inp.get("id"),
                    "value": inp.get("value"),
                    "placeholder": inp.get("placeholder"),
                    "required": inp.has_attr("required"),
                }
            )

        textareas = []
        for ta in form.find_all("textarea"):
            textareas.append(
                {
                    "tag": "textarea",
                    "name": ta.get("name"),
                    "id": ta.get("id"),
                    "placeholder": ta.get("placeholder"),
                    "required": ta.has_attr("required"),
                    "value_preview": (ta.text or "").strip()[:80],
                }
            )

        selects = []
        for sel in form.find_all("select"):
            options = []
            for opt in sel.find_all("option"):
                options.append(
                    {
                        "text": (opt.text or "").strip(),
                        "value": opt.get("value"),
                        "selected": opt.has_attr("selected"),
                    }
                )
            selects.append(
                {
                    "tag": "select",
                    "name": sel.get("name"),
                    "id": sel.get("id"),
                    "multiple": sel.has_attr("multiple"),
                    "required": sel.has_attr("required"),
                    "options": options,
                }
            )

        buttons = []
        for btn in form.find_all(["button"]):
            buttons.append(
                {
                    "tag": "button",
                    "type": (btn.get("type") or "submit").lower(),
                    "name": btn.get("name"),
                    "id": btn.get("id"),
                    "value": btn.get("value"),
                    "text": (btn.text or "").strip(),
                }
            )

        forms_info.append(
            {
                "index": idx,
                "id": form.get("id"),
                "name": form.get("name"),
                "class": " ".join(form.get("class", [])) if form.get("class") else None,
                "method": method,
                "action": action,
                "action_abs": action_abs,
                "inputs": inputs,
                "textareas": textareas,
                "selects": selects,
                "buttons": buttons,
            }
        )

    return forms_info


def print_report(forms: list[dict], url: str) -> None:
    if not forms:
        print(f"No se encontraron formularios en: {url}")
        return

    print("")
    print("=" * 80)
    print(f"Formularios encontrados en: {url}")
    print("=" * 80)

    for f in forms:
        print("")
        print(f"Formulario #{f['index']}")
        print("-" * 80)
        print(f"id: {f['id']}")
        print(f"name: {f['name']}")
        print(f"class: {f['class']}")
        print(f"method: {f['method']}")
        print(f"action: {f['action']}")
        print(f"action (absoluto): {f['action_abs']}")

        if f["inputs"]:
            print("\n  Inputs:")
            for i in f["inputs"]:
                print(
                    "    - tag=input | "
                    f"type={i['type']} name={i['name']} id={i['id']} "
                    f"placeholder={i['placeholder']} required={i['required']} value={i['value']}"
                )
        if f["textareas"]:
            print("\n  Textareas:")
            for t in f["textareas"]:
                print(
                    "    - tag=textarea | "
                    f"name={t['name']} id={t['id']} placeholder={t['placeholder']} "
                    f"required={t['required']} value_preview={t['value_preview']}"
                )
        if f["selects"]:
            print("\n  Selects:")
            for s in f["selects"]:
                print(
                    "    - tag=select | "
                    f"name={s['name']} id={s['id']} multiple={s['multiple']} required={s['required']}"
                )
                for opt in s["options"]:
                    print(
                        "        • option: "
                        f"text='{opt['text']}' value={opt['value']} selected={opt['selected']}"
                    )
        if f["buttons"]:
            print("\n  Botones:")
            for b in f["buttons"]:
                print(
                    "    - tag=button | "
                    f"type={b['type']} name={b['name']} id={b['id']} value={b['value']} text='{b['text']}'"
                )


def generate_value(base_text: str | None, suffix: str) -> str:
    base = base_text if base_text else random.choice(NAMES)
    if base:
        base = base[0].upper() + base[1:]
    n = random.randint(1, 9999)
    return f"{base}{n}{suffix}"


def build_form_payload(form: dict, base_value: str) -> dict:
    data: dict = {}

    # Inputs
    for i in form.get("inputs", []):
        name = i.get("name")
        if not name:
            continue
        t = (i.get("type") or "text").lower()
        if t in ("submit", "button", "image", "reset", "file"):
            continue
        if t in ("checkbox", "radio"):
            # Marcar con un valor simple si tiene value, si no, usar "on"
            val = i.get("value") or "on"
            data[name] = val
            continue
        if t in ("hidden",):
            data[name] = i.get("value") or base_value
            continue
        data[name] = base_value

    # Textareas
    for t in form.get("textareas", []):
        name = t.get("name")
        if not name:
            continue
        data[name] = base_value

    # Selects (usar opción seleccionada o la primera)
    for s in form.get("selects", []):
        name = s.get("name")
        if not name:
            continue
        options = s.get("options", [])
        value = None
        for opt in options:
            if opt.get("selected"):
                value = opt.get("value")
                break
        if value is None and options:
            value = options[0].get("value")
        data[name] = value if value is not None else ""

    return data


def submit_form(session: requests.Session, form: dict, base_url: str, timeout: int, user_agent: str | None, verify_tls: bool, data: dict) -> requests.Response:
    headers = {
        "User-Agent": user_agent
        or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
    }
    method = (form.get("method") or "GET").upper()
    action_abs = form.get("action_abs") or form.get("action") or base_url
    if not action_abs:
        action_abs = base_url
    if method == "GET":
        return session.get(action_abs, params=data, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
    else:
        return session.post(action_abs, data=data, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Detecta y lista formularios del index de una URL dada."
    )
    p.add_argument("url", nargs="?", help="URL a analizar (ej. https://ejemplo.com)")
    p.add_argument("--timeout", type=int, default=15, help="Timeout de la petición en segundos")
    p.add_argument(
        "--user-agent",
        type=str,
        default=None,
        help="User-Agent personalizado (opcional)",
    )
    p.add_argument(
        "--no-verify",
        action="store_true",
        help="No verificar certificados TLS (no recomendado)",
    )
    p.add_argument(
        "--pause",
        action="store_true",
        help="Pausar antes de salir (útil al ejecutar con doble clic)",
    )
    p.add_argument(
        "--ignore-status",
        action="store_true",
        help="Continuar aunque la respuesta sea 4xx/5xx (parsea el HTML devuelto si existe)",
    )
    p.add_argument(
        "--fill",
        action="store_true",
        help="Generar y mostrar un llenado automático del formulario (no envía)",
    )
    p.add_argument(
        "--submit",
        action="store_true",
        help="Enviar el formulario (por defecto ya se envía; use --no-submit para desactivar)",
    )
    p.add_argument(
        "--no-submit",
        action="store_true",
        help="No enviar el formulario automáticamente",
    )
    p.add_argument(
        "--times",
        type=int,
        default=None,
        help="Veces que se enviará automáticamente (si no se indica, se preguntará; por defecto 1)",
    )
    p.add_argument(
        "--form-index",
        type=int,
        default=1,
        help="Índice del formulario a usar (1 = primero)",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Segundos de espera entre envíos automáticos",
    )
    p.add_argument(
        "--api-url",
        type=str,
        default="",
        help="URL del backend para validar/descontar créditos (ej. https://tu-backend.com)",
    )
    p.add_argument(
        "--api-key",
        type=str,
        default="",
        help="API Key (Bearer) proporcionada por el backend tras el pago",
    )
    p.add_argument(
        "--base-text",
        type=str,
        default="",
        help="Texto base opcional (si no se indica, se usa un nombre de persona aleatorio)",
    )
    p.add_argument(
        "--suffix",
        type=str,
        default="#",
        help="Sufijo a agregar al valor generado (ej. '#')",
    )
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    url = args.url
    prompted = False
    if not url:
        url = input("Introduce la URL a analizar: ").strip()
        # Si se proporcionó por prompt, probablemente se ejecutó con doble clic.
        if url:
            prompted = True
    if not url:
        print("Debes indicar una URL.")
        if args.pause or prompted:
            try:
                input("Presiona Enter para salir...")
            except EOFError:
                pass
        return 2

    try:
        session = requests.Session()
        html = fetch_html_session(
            session,
            url,
            timeout=args.timeout,
            user_agent=args.user_agent,
            verify_tls=not args.no_verify,
            allow_error=args.ignore_status,
        )
    except requests.exceptions.HTTPError as e:
        # Si el servidor devolvió cuerpo, permitir continuar si el usuario lo pidió
        resp = getattr(e, "response", None)
        if resp is not None and args.ignore_status:
            html = resp.text
            print(f"Aviso: HTTP {resp.status_code}. Continuando por --ignore-status...")
        else:
            print(f"Error al descargar la página: {e}")
            if args.pause or prompted:
                try:
                    input("Presiona Enter para salir...")
                except EOFError:
                    pass
            return 1
    except requests.exceptions.RequestException as e:
        print(f"Error al descargar la página: {e}")
        if args.pause or prompted:
            try:
                input("Presiona Enter para salir...")
            except EOFError:
                pass
        return 1

    forms = extract_forms(html, base_url=url)
    print_report(forms, url)

    # Siempre generar y mostrar un payload de ejemplo para cada formulario detectado
    if forms:
        print("\n" + "=" * 80)
        print("Datos de ejemplo para rellenar automáticamente (no enviados):")
        print("=" * 80)
        for f in forms:
            base_value = generate_value(args.base_text, args.suffix)
            payload = build_form_payload(f, base_value)
            print(f"\nFormulario #{f['index']} - Payload sugerido:")
            for k, v in payload.items():
                print(f"  {k} = {v}")

    # Determinar cuántas veces enviar (si aplica)
    submit_times = 0
    if not args.no_submit:
        if args.times is not None:
            try:
                submit_times = max(1, int(args.times))
            except Exception:
                submit_times = 1
        else:
            try:
                times_in = input("¿Cuántas veces deseas enviar automáticamente? (Enter = 1): ").strip()
                submit_times = max(1, int(times_in)) if times_in else 1
                prompted = True
            except Exception:
                submit_times = 1

    # Enviar automáticamente salvo que se solicite no hacerlo
    if not args.no_submit and submit_times > 0:
        target_idx = max(1, int(args.form_index))
        form = next((ff for ff in forms if ff.get("index") == target_idx), None)
        if not form:
            print(f"No existe el formulario con índice {target_idx}.")
            if args.pause or prompted:
                try:
                    input("Presiona Enter para salir...")
                except EOFError:
                    pass
            return 1
        # Reservar créditos en backend si está configurado
        if args.api_url and args.api_key:
            try:
                api = args.api_url.rstrip("/") + "/api/use-credits"
                r = requests.post(
                    api,
                    headers={
                        "Authorization": f"Bearer {args.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={"count": int(submit_times)},
                    timeout=max(5, args.timeout),
                )
                r.raise_for_status()
                data = r.json()
                allowed = int(data.get("allowed", 0))
                remaining = int(data.get("remaining", 0))
                if allowed <= 0:
                    print("No tienes créditos disponibles para enviar.")
                    if args.pause or prompted:
                        try:
                            input("Presiona Enter para salir...")
                        except EOFError:
                            pass
                    return 1
                if allowed < submit_times:
                    print(f"Créditos disponibles: {allowed}. Se enviará solo {allowed} vez/veces.")
                else:
                    print(f"Créditos reservados: {allowed}. Restantes tras reserva: {remaining}.")
                submit_times = allowed
            except requests.exceptions.RequestException as e:
                print(f"Error al reservar créditos en el backend: {e}")
                if args.pause or prompted:
                    try:
                        input("Presiona Enter para salir...")
                    except EOFError:
                        pass
                return 1
        for attempt in range(1, submit_times + 1):
            base_value = generate_value(args.base_text, args.suffix)
            payload = build_form_payload(form, base_value)
            print(f"\nEnvío {attempt}/{submit_times} ...")
            try:
                resp = submit_form(session, form, url, args.timeout, args.user_agent, not args.no_verify, payload)
                print("Resultado del envío:")
                print(f"  Status: {resp.status_code}")
                print(f"  URL final: {resp.url}")
            except requests.exceptions.RequestException as e:
                print(f"Error al enviar el formulario: {e}")
                if args.pause or prompted:
                    try:
                        input("Presiona Enter para salir...")
                    except EOFError:
                        pass
                return 1
            if attempt < submit_times:
                time.sleep(max(0.0, float(args.interval)))
    if args.pause or prompted:
        try:
            input("\nPresiona Enter para salir...")
        except EOFError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
