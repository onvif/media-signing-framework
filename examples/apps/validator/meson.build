gstapp_dep = dependency(
  'gstreamer-app-@0@'.format(api_version),
  version : gst_req,
)
gstpbutils_dep = dependency(
  'gstreamer-pbutils-@0@'.format(api_version),
  version : gst_req,
)
jsonglib_dep = dependency('json-glib-1.0', version : '>= 1.6')

validator_sources = files(
  'main.c',
  'json_report.c',
)

executable('validator',
  validator_sources,
  include_directories : [ configinc, omssrcinc ],
  build_rpath : oms_lib_dir,
  install_rpath : oms_lib_dir,
  dependencies : [ gst_dep, gstapp_dep, gstpbutils_dep, jsonglib_dep ],
  link_with : mediasigningframework,
  install : true,
)

validator_json_report_test = executable('validator-json-report-test',
  'json_report_test.c',
  'json_report.c',
  include_directories : [ configinc, omssrcinc ],
  dependencies : [ jsonglib_dep ],
)
test('validator-json-report', validator_json_report_test)
