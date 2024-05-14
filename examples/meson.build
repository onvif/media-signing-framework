# project('signed-media-framework-examples', 'c',
#   version : '0.0.0',
#   meson_version : '>= 0.49.0',
#   default_options : [ 'warning_level=2',
#                       'werror=true',
#                       'buildtype=debugoptimized' ])
# 
# cc = meson.get_compiler('c')

prefix = get_option('prefix')

# cdata = configuration_data()
# cdata.set_quoted('VERSION', meson.project_version())
# configure_file(output : 'signed-media-framework-examples.pc', configuration : cdata)

# Explicitly include signed-media-framework
oms_lib = 'signed-media-framework'
oms_lib_dir = get_option('prefix') / get_option('libdir')
# oms_header_dir = get_option('prefix') / get_option('includedir')

#signedmediaframework_dep = declare_dependency(
#  link_args : [ '-L' + oms_lib_dir, '-l' + oms_lib ],
#  include_directories : include_directories(oms_header_dir),
#)

# gStreamer is used by all applications
gst_req = '>= 1.0.0'
api_version = '1.0'
gst_dep = dependency(
  'gstreamer-@0@'.format(api_version),
  version : gst_req,
)

subdir('apps')
