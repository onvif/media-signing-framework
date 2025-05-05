project('media-signing-framework', 'c',
  version : '1.0.2',
  meson_version : '>= 0.49.0',
  default_options : [ 'warning_level=2',
                      'werror=true',
                      'buildtype=debugoptimized' ])

cc = meson.get_compiler('c')

openssl_dep = dependency('openssl', required : true, version : '>=3.0.0')
check_dep = dependency('check', required : false)

if check_dep.found()
  # Option for code related to unit tests
  # Compile flag should not be used to change defines and settings in the lib
  add_global_arguments('-DOMS_UNIT_TEST', language : 'c')
endif

if get_option('debugprints')
  add_global_arguments('-DONVIF_MEDIA_SIGNING_DEBUG', language : 'c')
endif
if get_option('parsesei')
  add_global_arguments('-DPRINT_DECODED_SEI', language : 'c')
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
configure_file(output : 'media-signing-framework.pc', configuration : cdata)

configinc = include_directories('.')

subdir('lib')

# Create a shared library and generate a pkgconfig
install_headers(
    mediasigningframework_public_headers,
    install_dir : '@0@/media-signing-framework'.format(get_option('includedir')))

mediasigningframework_deps = [ openssl_dep, plugin_deps ]

mediasigningframework = shared_library(
    'media-signing-framework',
    mediasigningframework_sources,
    include_directories : [ omssrcinc ],
    version : meson.project_version(),
    dependencies : mediasigningframework_deps,
    install : true,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
    mediasigningframework,
    name : 'media-signing-framework',
    description : 'ONVIF Media Signing Framework',
)

if (get_option('signer') or get_option('validator') or get_option('build_all_apps'))
  subdir('examples')
else
  subdir('tests')
endif
