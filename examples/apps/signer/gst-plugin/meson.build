gstbase_dep = dependency(
  'gstreamer-base-@0@'.format(api_version),
  version : gst_req
)

gstsigning_sources = files(
  'gst-signing-plugin.c',
  'gstsigning.c',
  'gstsigning.h',
  'gstsigning_defines.h',
)

# For gst, store configuration data in config.h
appcdata = configuration_data()
appcdata.set_quoted('VERSION', meson.project_version())
appcdata.set_quoted('PACKAGE', meson.project_name())
appcdata.set_quoted('GST_PACKAGE_NAME', meson.project_name())
configure_file(output : 'config.h', configuration : appcdata)

gstsigning_args = [ '-DHAVE_CONFIG_H' ]

gstsigninginc = include_directories('.')

gstsigning = shared_library('gstsigning',
  gstsigning_sources,
  c_args : gstsigning_args,
  include_directories : [ configinc, gstsigninginc ],
  build_rpath : oms_lib_dir,
  install_rpath : oms_lib_dir,
  dependencies : [ gst_dep, gstbase_dep ],
  link_with : mediasigningframework,
  install : true,
)
