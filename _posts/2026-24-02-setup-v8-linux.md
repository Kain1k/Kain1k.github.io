---
title: "Setting Up V8 for CTF Browser Exploitation (Linux)"
date: 2026-02-24 02:00:00 +0800
categories: [Browser Exploitation, Chrome]
tags: [Chrome Exploitation, Browser Exploitation, CTF]
---

I am focusing more on browser pwn to improve my skills. However, browser challenges, especially V8 challenges, are usually designed to run on Linux. The exploit code is also expected to run on Linux.

In this blog, I will set up an environment so that for each challenge, I can build V8 easily and avoid using too much disk space. I will use the Krautflare challenge from 35C3 CTF as an example. You can easily find this challenge online.

Before building, we will go through the common files that usually appear in browser challenges.
![](ls_chall.png)
Look at the image below. There are several important files we should pay attention to: the `build.sh` file, the `patch` file, the `bin` file, and the provided `d8` program.

The `d8` file given in the challenge is actually a release build. The `bin` file is a memory snapshot created after a successful build. It contains objects such as Object, Array, String, Math, JSON, built-in functions, and many other internal components. This file is provided to make sure your local environment matches the challenge environment on the organizer’s server.

If you notice, I also have another file called `d8_debug`. That is our build target. The release version does not support some useful commands and flags that help during exploitation, so we need to build a debug version.

However, there is one problem. When we build the debug version, it may generate files that are different from the organizer’s version, such as the `bin` snapshot file. This can affect techniques that require exact offsets, like building a ROP chain. But, from what I have seen, if we use the WASM jump table overwrite technique, it may work on both versions because this technique does not rely on exact offsets.

So the debug build is mainly used for testing, to check whether we can trigger the bug. In the end, our final exploit must work on the release version provided by the challenge.

Next is the `patch` file. This file is created by the organizers to reproduce the intended bug and control the conditions of the challenge. It forces us to follow the intended exploitation path instead of simply using something like a print command to directly show the flag. We need to read the `patch` file to identify the vulnerability. When we build the debug version, we also need to apply these `patch` files so that our environment is as close as possible to the original challenge setup. I will explain how to do this later.

Finally, there is the `build.sh` file. This file helps us build V8 by ourselves. The original file provided by the organizers looks like below.

![](buildsh.png)

As you can see, this script fetches V8 every time it runs. If you work on many challenges and fetch V8 many times, it will waste a lot of disk space. So I will modify it a bit, so that I can build V8 for different challenges while fetching the source code only once.

## Building
The first step is to install [depot_tools](https://commondatastorage.googleapis.com/chrome-infra-docs/flat/depot_tools/docs/html/depot_tools_tutorial.html#_setting_up). You should add it to your `~/.bashrc` file so you don’t have to export the PATH every time you open a new terminal.
```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
```

After that, you need to install Python 2. Many challenges are based on old vulnerabilities and still require Python 2. I installed it by following this [guide](https://askubuntu.com/questions/1527867/python-2-7-12-install-on-ubuntu-22-04#:~:text=6-,python2.,7.18%2D13ubuntu1.5_amd64.deb). You can check it with the following command, and you should see Python 2.7 installed.
```bash
ls /usr/bin/python*
```

Next, you need to create a symlink. Even though you have Python 2 installed, it may appear as `python2.7`. This can cause the build to fail because the build system may only recognize `python2` or `python`. So creating a symlink will help avoid this issue.

```bash
sudo ln -s /usr/bin/python2.7 /usr/bin/python
sudo ln -s /usr/bin/python2.7 /usr/bin/python2
```

You should see this.

![](python_star.png)

You will also need to install many packages listed below. If you get errors because something is missing, you can use AI tools like ChatGPT to help you fix them.
```bash
sudo apt install pkg-config
sudo apt install libglib2.0-dev
sudo apt install build-essential
sudo apt install libgtk-3-dev
sudo apt install libnss3-dev
sudo apt install libx11-dev
sudo apt install libxcomposite-dev
sudo apt install libxdamage-dev
sudo apt install libxrandr-dev
sudo apt install libgbm-dev
sudo apt install libasound2-dev
sudo apt install libatk1.0-dev
sudo apt install libcups2-dev
sudo apt install libxss-dev

sudo apt install ninja-build
```

Okay, at this point, you should be able to fetch V8. This will take some time and create a separate v8 directory. We will use this single V8 source directory to build for different challenges, so we don’t need to fetch it again each time.

```bash
fetch v8
cd v8
```

When you succeed and see the v8 directory, we are ready to build. But before building, I want to show you an overview of the file structure.
```
Browser/
   v8/
   chall 1/
       build.sh
       patch.patch
   chall 2/ 
```

Mine looks like this.
```
Home/Browser/
    v8/
    krautflare/
        build_v8.sh
        d8-strip-globals.patch
        revert-bugfix-880207.patch
        open_files_readonly.patch
```

Remember the `build.sh` file? We will modify it so that it uses this existing v8 directory as the source for building.
![](buildsh_modify.png)
```
#!/bin/bash
set -euxo pipefail

pushd ~/Browser/v8

git reset --hard
git clean -fd

git checkout dde25872f58951bb0148cf43d6a504ab2f280485

git apply ~/Browser/krautflare/d8-strip-globals.patch
git apply ~/Browser/krautflare/revert-bugfix-880207.patch
git apply ~/Browser/krautflare/open_files_readonly.patch

gclient sync

./tools/dev/gm.py x64.debug

popd
```

If you look at my modified script, you can see that it still checks out the correct commit and applies the patch files, just like the original `build.sh` from the organizers.

However, I removed the step that fetches V8, because now it points to the shared V8 directory we created earlier. I also changed the build target from `x64.release` to `x64.debug` so we can build the debug version.

You may also notice two commands: `git reset --hard` and `git clean -fd`. These commands make sure that when we build for another challenge, all old `patch` files and `changes` are removed. This way, we can safely apply new patches without conflicts.

You can also modify the script a little more so it can copy or generate a new d8 binary for a different challenge, like this.
```
#!/bin/bash
set -euxo pipefail

pushd ~/Browser/v8

git reset --hard
git clean -fd

git checkout <other commit>

git apply /path to patch 1
git apply /path to patch 2
git apply /path to patch 3

gclient sync

./tools/dev/gm.py x64.debug

popd
```

After the build finishes successfully, you will find the debug version of d8 in `/v8/out/x64.debug`.

Actually, I just copied the binary debug file into the challenge folder as before so it's easier for you to see.

If you run `d8` outside of the `x64.debug` directory, it will not work because it depends on other required files in that folder. You can either copy the whole `x64.debug` directory into your challenge folder, or simply run it using the full path like this. You can also use the `file` command to check whether it is a debug build or not.

![](path_debug.png)

That’s it. Good luck!


