project('media-signing-mcp-demo', 'c',
  version : '0.1.0',
  meson_version : '>= 0.51.0',
  default_options : [ 'warning_level=2', 'werror=true', 'buildtype=debugoptimized' ])

gst_req = '>=1.0'
gst_dep = dependency('gstreamer-1.0', version : gst_req)
gstapp_dep = dependency('gstreamer-app-1.0', version : gst_req)
gstpbutils_dep = dependency('gstreamer-pbutils-1.0', version : gst_req)
jsonglib_dep = dependency('json-glib-1.0', version : '>=1.6')
oms_dep = dependency('media-signing-framework', required : true)
oms_lib_dir = oms_dep.get_variable(pkgconfig : 'libdir')

executable('media-signing-mcp-validator',
  'main.c',
  build_rpath : oms_lib_dir,
  install_rpath : oms_lib_dir,
  dependencies : [ gst_dep, gstapp_dep, gstpbutils_dep, jsonglib_dep, oms_dep ],
  install : true,
)
