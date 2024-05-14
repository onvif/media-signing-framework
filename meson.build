project('signed-media-framework', 'c',
  version : '0.0.0',
  meson_version : '>= 0.49.0',
  default_options : [ 'warning_level=2',
                      'werror=true',
                      'buildtype=debugoptimized' ])

cc = meson.get_compiler('c')

check_dep = dependency('check', required : false)

if check_dep.found()
  # Option for code related to unit tests
  # Compile flag should not be used to change defines and settings in the lib
  add_global_arguments('-DOMS_UNIT_TEST', language : 'c')
endif

if get_option('debugprints')
  add_global_arguments('-DONVIF_MEDIA_SIGNING_DEBUG', language : 'c')
endif

signing_plugin = get_option('signingplugin')
# Determine if 'threaded_unless_check_dep' should use 'threaded' or 'unthreaded'
if (signing_plugin == 'threaded_unless_check_dep' and check_dep.found())
  signing_plugin = 'unthreaded'
elif (signing_plugin == 'threaded_unless_check_dep')
  signing_plugin = 'threaded'
endif


cdata = configuration_data()
cdata.set_quoted('VERSION', meson.project_version())
configure_file(output : 'signed-media-framework.pc', configuration : cdata)

configinc = include_directories('.')

subdir('lib')
subdir('tests')
if (get_option('signer') or get_option('validator') or get_option('build_all_apps'))
  subdir('examples')
endif
