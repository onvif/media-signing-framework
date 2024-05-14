gstapp_dep = dependency(
  'gstreamer-app-@0@'.format(api_version),
  version : gst_req,
)

validator_sources = files(
  'main.c'
)

executable('validator',
  validator_sources,
  include_directories : [ configinc ],
  build_rpath : oms_lib_dir,
  install_rpath : oms_lib_dir,
  dependencies : [ gst_dep, gstapp_dep ],
  link_with : signedmediaframework,
  install : true,
)
