#! /usr/bin/env python3
# clovervidia
import aiohttp.web
import frida
import json
import logging
import shutil
import subprocess
import time
import uuid

routes = aiohttp.web.RouteTableDef()

required_payload_keys = {"hash_method", "token"}
expected_payload_keys = {"timestamp", "request_id", "hash_method", "token"}

script = None


def setup():
    # Check for adb on the PATH
    if not shutil.which("adb"):
        raise RuntimeError("Couldn't find adb executable. Is it installed and in your PATH?")

    # Connect to the Android device using adb
    logging.info("Connecting to the Android device using adb...")
    output = subprocess.run(["adb", "connect", f'{settings["android_device_ip"]}:{settings["android_device_port"]}'],
                            capture_output=True, text=True)
    if "connected" not in output.stdout:
        raise RuntimeError("Couldn't connect to the Android device. Double-check the IP address in config.json.")
    logging.info("Connected.")

    # Locate the Android device. If it's connected to adb, it will appear as a USB device to Frida.
    logging.info("Searching for Android device...")
    frida.enumerate_devices()
    time.sleep(1)
    try:
        device = frida.get_usb_device()
    except frida.InvalidArgumentError:
        raise RuntimeError("Couldn't find the Android device. Is it connected to adb? Double-check the IP address in"
                           "config.json.")
    logging.info(f"Located Android device at {device.id}.")

    # Get the PID of the NSO app if it's running, or launch it if it isn't
    logging.info("Launching NSO app...")
    try:
        process = device.get_process("Nintendo Switch Online")
        pid = process.pid
    except frida.ProcessNotFoundError:
        try:
            pid = device.spawn(["com.nintendo.znca"])
            device.resume(pid)
        except frida.NotSupportedError:
            raise RuntimeError("Couldn't connect to the Frida server on the Android device. Is it running?")
    except frida.ServerNotRunningError:
        raise frida.ServerNotRunningError("Couldn't connect to the Frida server on the Android device. Is it running?")
    logging.info("NSO app launched.")

    # Attach to the NSO app and export functions from Frida that provide access to those two libvoip functions
    try:
        session = device.attach(pid)
    except frida.ServerNotRunningError:
        raise frida.ServerNotRunningError("Couldn't connect to the Frida server on the Android device. Is it running?")

    global script
    script = session.create_script("""
    rpc.exports = {
        genAudioH(token, timestamp, request_id) => {
            return new Promise(resolve => {
                Java.perform(() => {
                    const libvoipjni = Java.use("com.nintendo.coral.core.services.voip.LibvoipJni");
                    var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    libvoipjni.init(context);
                    timestamp = !timestamp ? Date.now() : timestamp;
                    resolve({
                        "f": libvoipjni.genAudioH(token, timestamp.toString(), request_id),
                        "timestamp": parseInt(timestamp),
                        "request_id": request_id
                    });
                });
            });
        },
        genAudioH2(token, timestamp, request_id) => {
            return new Promise(resolve => {
                Java.perform(() => {
                    const libvoipjni = Java.use("com.nintendo.coral.core.services.voip.LibvoipJni");
                    var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    libvoipjni.init(context);
                    timestamp = !timestamp ? Date.now() : timestamp;
                    resolve({
                        "f": libvoipjni.genAudioH2(token, timestamp.toString(), request_id),
                        "timestamp": parseInt(timestamp),
                        "request_id": request_id
                    });
                });
            });
        }
    }
    """)
    script.load()


def gen_audio_h(token: str, timestamp: str = None, request_id: str = None) -> str:
    if not script:
        raise RuntimeError("Run setup() to connect to the Android device before attempting to generate tokens")
    if not request_id:
        request_id = str(uuid.uuid4())
    return script.exports.gen_audio_h(str(token), str(timestamp) if timestamp else None, str(request_id))


def gen_audio_h2(token: str, timestamp: str = None, request_id: str = None) -> str:
    if not script:
        raise RuntimeError("Run setup() to connect to the Android device before attempting to generate tokens")
    if not request_id:
        request_id = str(uuid.uuid4())
    return script.exports.gen_audio_h2(str(token), str(timestamp) if timestamp else None, str(request_id))


@routes.post("/f")
async def generate_f_token(request: aiohttp.web.Request):
    # Verify that the response's Content-Type implies JSON data and that the body contains data
    if request.content_type != "application/json":
        return aiohttp.web.json_response({"error": True, "reason": "Unsupported Media Type"}, status=415)
    if not request.body_exists:
        return aiohttp.web.json_response({"error": True, "reason": "Unprocessable Entity"}, status=422)

    # Verify that the body contains valid JSON data
    try:
        payload = await request.json()
    except json.decoder.JSONDecodeError:
        return aiohttp.web.json_response({"error": True, "reason": "The given data was not valid JSON."}, status=400)

    # Verify that the payload contains the required keys
    if not set(payload.keys()).issuperset(required_payload_keys):
        missing_keys = required_payload_keys - set(payload.keys())
        return aiohttp.web.json_response({"error": True, "reason": f"Value required for keys '{missing_keys}'."},
                                         status=400)

    # Verify that the payload's values are all strings
    for key, value in payload.items():
        if key not in expected_payload_keys:
            continue
        if not isinstance(value, str):
            return aiohttp.web.json_response(
                {"error": True, "reason": f"Value of type 'String' required for key '{key}'."}, status=400)

    # Verify that the hash method is a valid int and set to either 1 or 2
    try:
        if int(payload["hash_method"]) not in (1, 2):
            return aiohttp.web.json_response(
                {"error": True, "reason": f"Invalid value {payload['hash_method']} for key hash_method"}, status=400)
    except ValueError:
        return aiohttp.web.json_response(
            {"error": True, "reason": f"Invalid value '{payload['hash_method']}' for key hash_method"}, status=400)

    # Verify that the timestamp, if present, is a valid int
    if payload.get("timestamp"):
        try:
            int(payload["timestamp"])
        except ValueError:
            return aiohttp.web.json_response({"error": True, "reason": "Something went wrong."}, status=500)

    # If everything else checked out, call the appropriate exported function from Frida
    if payload["hash_method"] == "1":
        return aiohttp.web.json_response(gen_audio_h(payload["token"], payload.get("timestamp"),
                                                     payload.get("request_id")))
    else:
        return aiohttp.web.json_response(gen_audio_h2(payload["token"], payload.get("timestamp"),
                                                      payload.get("request_id")))


if __name__ == "__main__":
    from config import settings

    logging.basicConfig(level=logging.INFO)
    setup()
    app = aiohttp.web.Application()
    app.add_routes(routes)
    aiohttp.web.run_app(app, port=settings["web_server_port"])
else:
    from .config import settings
