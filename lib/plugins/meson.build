# The Media Signing Framework currently have two signing plugins; 'unthreaded' (default) and
# 'threaded'.
# For simplicity, the 'plugin.c' file is selected based on the meson option 'signingplugin' and
# added to the source files of media-signing-framework.

if (signing_plugin == 'unthreaded')
  subdir('unthreaded-signing')
elif (signing_plugin == 'threaded')
  subdir('threaded-signing')
else
  message('Unknown signing plugin: \'' + signing_plugin + '\'')
endif
