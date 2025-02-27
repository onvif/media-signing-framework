*Copyright (c) 2025 ONVIF. All rights reserved.*

# The ONVIF Media Signing Framework library
```
lib
├── plugins
|   ├── threaded-signing
|   |   └── plugin.c
|   └── unthreaded-signing
|       └── plugin.c
└── src
    ├── includes
    |   └── public header files
    └── source files
```

The library is organized in [source code](./src/) and [plugins](./plugins/).
The source code includes all necessary source files for both signing and validation, and
there is no conceptual difference in building the library for signing or for validation.

The signing part of the code uses signing plugin calls. A plugin should be implemented
following the interfaces in
[onvif_media_signing_plugin.h](./src/includes/onvif_media_signing_plugin.h). The framework
comes with both a threaded and an unthreaded signing plugin. When building the library
with the meson structure in this repository, the library includes one of these plugins,
depending on meson options.
