prefix = get_option('prefix')

# Explicitly include signed-media-framework
oms_lib = 'signed-media-framework'
oms_lib_dir = get_option('prefix') / get_option('libdir')

# gStreamer is used by all applications
gst_req = '>= 1.0.0'
api_version = '1.0'
gst_dep = dependency(
  'gstreamer-@0@'.format(api_version),
  version : gst_req,
)

subdir('apps')
