# NSO Token Gen

In order to authenticate to Nintendo's web services to use things like SplatNet 2 or NookLink, you need a token that
the NSO app generates. It uses a native library to generate these tokens, and unfortunately, the easiest way to generate
them on a computer is to use an Android device to access that native library.

This is a Python program that uses Frida to talk to an Android device and generate those tokens using that native
library. It also uses aiohttp to run a local web service that you can access from your own programs to obtain those
tokens.

Note that due to the way Frida works, you will need a rooted Android device. I did my testing using an Android x86 VM
in VirtualBox, as I don't have a physical rooted device, but it should work on either type of device.

Inspired in part by [nxapi](https://github.com/samuelthomas2774/nxapi), which performs a similar function using Frida
and an Android device in JS. I spent some time trying out Frida before, and I learned how to call functions within the
NSO app, but I didn't have any ideas on how to turn  that into a service that programs could use to generate
tokens until I saw nxapi's implementation. 

If you're using [splatnet2statink](https://github.com/frozenpandaman/splatnet2statink), with some minimal changes to
`iksm.py`, you can use nsotokengen to generate f tokens as part of the authentication process if you want to generate
your tokens locally. See [the wiki](https://github.com/clovervidia/nsotokengen/wiki/splatnet2statink) for instructions
on the specific changes to make.  
The same goes for [s3s](https://github.com/frozenpandaman/s3s), but it's even easier because you just have to change a
setting in the config file. Check [the wiki](https://github.com/clovervidia/nsotokengen/wiki/s3s) for more information.

## Setup

The setup process is rather similar to nxapi's setup. You'll need a rooted Android device and a computer with `adb` to
communicate with it. You'll also need to install the Frida server and the NSO app on the rooted device.

Follow these instructions to set up Android x86 as a VM on your computer if you don't have a physical rooted device to
use: https://www.android-x86.org/installhowto.html

Then, follow these instructions to install the Frida server on your Android device: https://frida.re/docs/android/

If you don't have `adb`, you can download it from here: https://developer.android.com/studio/releases/platform-tools  
Make sure you add it to your system's `PATH` variable, as `nsotokengen` will call it to connect to your Android device. 

Rename the `config.json.sample` file to `config.json` and set the `android_device_ip` to the IP address of your Android
device. If you're using a port other than `5555` for `adb`, change `android_device_port` as well.

The web server will listen on port `8080` by default, and this can be changed through the config file if you have
another service running on that port.

## Usage

Once you've installed the Python requirements and set up your Android device, you should be ready to run the program.

There are two ways to use nsotokengen. You can run it directly to start the web service and generate tokens by POSTing
data to it. Or, you can import nsotokengen into your Python project as a package and call its functions directly. 

### As a Web Service

Run `nsotokengen.py`. It will verify that `adb` is available on the `PATH`, then it will use it to connect to your
Android device, and then it will connect to the Frida server running on it. If anything doesn't work, it'll print an
error message that should help you figure out what went wrong. 

To test out the web service once it's running, use `curl` or a similar tool to hit `localhost:8080/f`. You should get
back a `405: Method Not Allowed` error. That's just because the endpoint on the web service only responds to `POST`
requests.

I modeled the API after the [imink API](https://github.com/JoneWang/imink/wiki/imink-API-Documentation), as it seemed to
use a fairly sensible design. As such, the API expects JSON data to be POSTed to it, and it will respond with JSON data.

You'll need to provide the following keys and values:

|Key|Value|
|:---|:---|
|`hashMethod` or `hash_method`|`1` for the first half of the authentication process and `2` for the second|
|`token`|Your access token from earlier in the Nintendo authentication process|

Due to changes in how the NSO authentication process works, nsotokengen will now handle generating the timestamp and
request ID.

`POST` a JSON to the API and you'll get a JSON response back. If there's a key named `error`, something went wrong, and
you should check the `reason` key to figure out what happened. Otherwise, there will be three keys, named `f`,
`timestamp`, and `request_id`. Since nsotokengen now generates the timestamp and request ID, those values will be sent
in the response, along with the `f` token, and you'll need to use those values when authenticating to NSO.

### As a Package

To use nsotokengen as a package in your Python project, start by importing it:

```python
import nsotokengen
```

Next, call `nsotokengen.setup()` to connect to the Android device. It's recommended that you print a message and wait
for user confirmation before you call this so that users can start their Android devices and get everything set up
first.

```python
nsotokengen.setup()
```

If anything goes wrong, a `RuntimeError` will be raised with a description of what happened.

Sometimes, Frida isn't able to connect to the Frida server running on the Android device, even though it's running.
nsotokengen will raise a `frida.ServerNotRunningError` if this occurs. For this reason, you might want to run
`nsotokengen.setup()` a few times in a loop, just to make sure it's able to connect, as the connection issues usually
work themselves out if you try to connect a few times.

Once the setup is complete, you can now generate both types of tokens using the following functions:

```python
nsotokengen.gen_audio_h("token_goes_here")
nsotokengen.gen_audio_h2("token_goes_here")
```

You'll receive a dictionary containing the generated token, the timestamp, and the request ID. Since nsotokengen now
generates the timestamp and request ID, you'll need to use the values returned from the functions when authenticating to
NSO.

## Other Interesting Projects

I got the idea to write this program after seeing [nxapi](https://github.com/samuelthomas2774/nxapi), as it has a
similar component that uses Frida to connect to a rooted Android device to generate f tokens. It was written in JS,
which is a language I haven't used, so I thought I'd try writing something similar in Python.  
nxapi actually does a lot more than just generate those tokens. It provides a way to access the services NSO lets you
use on your phone, like SplatNet 2 and NookLink, but right on your computer. You should check it out.

[imink](https://github.com/JoneWang/imink) is an iOS app that provides an alternate interface to the data SplatNet 2
provides, like your battle results and map schedules. The creator of the app stood up a web service to generate f tokens
and was gracious enough to provide public API documentation for its use. If you don't want to set up nxapi or
nsotokengen locally, you can use the imink API to generate f tokens for your program.

[splatnet2statink](https://github.com/frozenpandaman/splatnet2statink) is a project I worked on that can download your
Splatoon 2 battle logs from SplatNet 2 and upload them to [stat.ink](https://stat.ink) to track your battle stats.   
[s3s](https://github.com/frozenpandaman/s3s) is the successor to splatnet2statink that works with SplatNet 3 to track
your Splatoon 3 battles.
