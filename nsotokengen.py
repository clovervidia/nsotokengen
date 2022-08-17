#! /usr/bin/env python3
# clovervidia
import aiohttp.web
import config
import frida
import json
import logging
import shutil
import subprocess
import sys
import time

routes = aiohttp.web.RouteTableDef()

expected_payload_keys = {"timestamp", "request_id", "hash_method", "token"}

# Check for adb on the PATH
if not shutil.which("adb"):
    print("Couldn't find adb executable. Is it installed and in your PATH?")
    sys.exit(1)

# Connect to the Android device using adb
print("Connecting to the Android device using adb...")
subprocess.call(["adb", "connect", f'{config.settings["android_device_ip"]}:{config.settings["android_device_port"]}'])

# Locate the Android device. If it's connected to adb, it will appear as a USB device to Frida.
print("Searching for Android device...")
frida.enumerate_devices()
time.sleep(1)
try:
    device = frida.get_usb_device()
except frida.InvalidArgumentError:
    print("Couldn't find the Android device. Is it connected to adb? Double-check the IP address in config.json.")
    sys.exit(1)
print(f"Located Android device at {device.id}.")

# Get the PID of the NSO app if it's running, or launch it if it isn't
print("Launching NSO app...")
try:
    process = device.get_process("Nintendo Switch Online")
    pid = process.pid
except frida.ProcessNotFoundError:
    try:
        pid = device.spawn(["com.nintendo.znca"])
        device.resume(pid)
    except frida.NotSupportedError:
        print("Couldn't connect to the Frida server on the Android device. Is it running?")
        sys.exit(1)
print("NSO app launched.")

# Attach to the NSO app and export functions from Frida that provide access to those two libvoip functions
try:
    session = device.attach(pid)
except frida.ServerNotRunningError:
    print("Couldn't connect to the Frida server on the Android device. Is it running?")
    sys.exit(1)

script = session.create_script("""
rpc.exports = {
    genAudioH(token, timestamp, uuid) => {
        return new Promise(resolve => {
            Java.perform(() => {
                const libvoipjni = Java.use("com.nintendo.coral.core.services.voip.LibvoipJni");
                var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                libvoipjni.init(context);
                resolve(libvoipjni.genAudioH(token, timestamp, uuid));
            });
        });
    },
    genAudioH2(token, timestamp, uuid) => {
        return new Promise(resolve => {
            Java.perform(() => {
                const libvoipjni = Java.use("com.nintendo.coral.core.services.voip.LibvoipJni");
                var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                libvoipjni.init(context);
                resolve(libvoipjni.genAudioH2(token, timestamp, uuid));
            });
        });
    }
}
""")
script.load()


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

    # Verify that the payload contains the expected keys
    if not set(payload.keys()).issuperset(expected_payload_keys):
        missing_keys = expected_payload_keys - set(payload.keys())
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

    # If everything else checked out, call the appropriate exported function from Frida
    if payload["hash_method"] == "1":
        return aiohttp.web.json_response(
            {"f": script.exports.gen_audio_h(payload["token"], payload["timestamp"], payload["request_id"])})
    else:
        return aiohttp.web.json_response(
            {"f": script.exports.gen_audio_h2(payload["token"], payload["timestamp"], payload["request_id"])})


if __name__ == "__main__":
    app = aiohttp.web.Application()
    app.add_routes(routes)
    logging.basicConfig(level=logging.DEBUG)
    aiohttp.web.run_app(app, port=config.settings["web_server_port"])
