#! /usr/bin/env python3
# clovervidia
import ipaddress
import json
import pathlib

config_file_name = "config.json"
config_file_path = pathlib.Path(__file__).parent.absolute() / config_file_name
default_settings = {"web_server_port": 8080, "android_device_ip": "192.168.1.1", "android_device_port": 5555}
settings = None

if not config_file_path.exists():
    with open(config_file_path, "w", encoding="utf8") as file:
        json.dump(default_settings, file, indent=4)
    settings = default_settings
else:
    with open(config_file_path, encoding="utf8") as file:
        settings = json.load(file)

if not set(settings.keys()).issuperset(default_settings.keys()):
    raise KeyError(f"Config file is missing the following keys: {default_settings.keys() - set(settings.keys())}")

for port in ("web_server_port", "android_device_port"):
    if not isinstance(settings[port], int):
        raise TypeError(f'"{port}" should be an int, got {type(settings[port])}')
    if not 1 <= settings[port] <= 65535:
        raise ValueError(f'"{port}" should be a valid port between 1 and 65535, got {settings[port]}')

try:
    ipaddress.ip_address(settings["android_device_ip"])
except ValueError:
    raise ValueError(f'"android_device_ip" was not set to a valid IP address, got {settings["android_device_ip"]}')

if __name__ == "__main__":
    print(json.dumps(settings, indent=4))
