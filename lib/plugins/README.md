*Copyright (C) 2024, ????*

# ONVIF Signed Media Framework plugins
Signing using a private key is usually done in a secure part of a device. This usually
requires device specific operations which cannot be generalized to an open source project.
Therefore, the framework supports signing through a concept of plugins.

The ONVIF Signed Media Framework comes with implementations of two plugins;
[unthreaded-signing/plugin.c](./unthreaded-signing/plugin.c) and
[threaded-signing/plugin.c](./threaded-signing/plugin.c). Both of them use OpenSSL APIs
to generate signatures.

It is safe to use any of these plugins in a multi-threaded integration.

## Unthreaded plugin
The unthreaded plugin blocks further operations until the signature has been generated.
This is the default plugin. The check tests only work with this plugin. Further, the
validation does not need a signing plugin, but since there currently is no option to
select side it is preferred to use the unthreaded plugin (default) when building for
validation.

## Threaded plugin
The threaded plugin calls the OpenSSL signing APIs from a separate thread. If the plugin
is initialized using `onvif_media_signing_plugin_init()` a central thread is spawned. If
the user runs multiple sessions they share the same input and output buffers. If the
plugin is not initialized as above, signing is done from a local thread in each session.
This can cause quite some threads if multiple streams are signed.

This implementation requires [glib-2.0](https://docs.gtk.org/glib/).

## Selecting a plugin
Through the meson option `signingplugin`, one of them can be selected and the source file
is added to the library sources. There is one extra option (`threaded_unless_check_dep`)
which can be set if the signing side should be built with a threaded plugin unless
libcheck exists. The unthreaded plugin is the library default.

## Creating a plugin
It is feasible to build your own signing plugin. The only requirement is to implement the
interfaces declared in
[onvif_media_signing_plugin.h](../src/includes/onvif_media_signing_plugin.h). For
examples, see [unthreaded-signing/plugin.c](./unthreaded-signing/plugin.c) and
[threaded-signing/plugin.c](./threaded-signing/plugin.c).

## Loading a plugin
The ONVIF Signed Media Framework does not support arbitrary plugins out of the box. It is
up to the user to make sure to build with a self made signing plugin.
