# Pipewire driver for Microsoft Kinect (v1)

This is a userspace driver for microphone assembly of Microsoft Kinect for Xbox 360. It generally needs firmware at runtime, but I, with very high chances cannot tell you where, how, and whether you can get it. Kinect SDK for Windows should have one.

## Build Instructions

### Dependencies
- libfreenect
- pipewire >= 0.3
- meson
- pthread

### Building
    git clone https://github.com/zinstack625/kinect_pipewire
    cd kinect_pipewire
    meson setup build
    cd build
    meson compile
    
    # for installation
    meson install
    # and load module in pipewire. The only way I know as of now is to include it in pipewire config (look for docs)

# Licence
A mashup of code from libfreenect and pipewire makes a mashup of Apache v2 and MIT licenses. If you're a lawyer and know better, tell me
```
This file is part of the OpenKinect Project. http://www.openkinect.org

Copyright (c) 2010 individual OpenKinect contributors. See the CONTRIB
file for details.

This code is licensed to you under the terms of the Apache License,
version 2.0, or, at your option, the terms of the GNU General Public
License, version 2.0. See the APACHE20 and GPL2 files for the text of
the licenses, or the following URLs:
http://www.apache.org/licenses/LICENSE-2.0
http://www.gnu.org/licenses/gpl-2.0.txt

If you redistribute this file in source form, modified or unmodified,
you may:

- Leave this header intact and distribute it under the same terms,
  accompanying it with the APACHE20 and GPL2 files, or
- Delete the Apache 2.0 clause and accompany it with the GPL2 file, or
- Delete the GPL v2 clause and accompany it with the APACHE20 file

In all cases you must keep the copyright notice intact and include a
copy of the CONTRIB file.

Binary distributions must follow the binary distribution requirements
of either License.
```
```
PipeWire

Copyright © 2021 Wim Taymans

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice (including the next
paragraph) shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

# Code Contribution

If you managed to get yourself in a sticky situation and want to contribute, please feel free to. The only thing I want is that you preserve history of commits.
