signedmediaframework_public_headers = files(
  'includes/onvif_media_signing_common.h',
  'includes/onvif_media_signing_helpers.h',
  'includes/onvif_media_signing_plugin.h',
  'includes/onvif_media_signing_signer.h',
  'includes/onvif_media_signing_validator.h',
)

signedmediaframework_sources = files(
  'oms_authenticity_report.c',
  'oms_authenticity_report.h',
  'oms_common.c',
  'oms_defines.h',
  'oms_helpers.c',
  'oms_internal.h',
  'oms_nalu_list.c',
  'oms_nalu_list.h',
  'oms_openssl.c',
  'oms_openssl_internal.h',
  'oms_signer.c',
  'oms_tlv.c',
  'oms_tlv.h',
  'oms_validator.c',
)

# Until plugin management is in place the plugin file(s) are added to the sources.
signedmediaframework_sources += plugin_sources

openssl_dep = dependency('openssl', required : true, version : '>=3.0.0')

install_headers(
    signedmediaframework_public_headers,
    install_dir : '@0@/signed-media-framework'.format(get_option('includedir')))

signedmediaframework_deps = [ openssl_dep, plugin_deps ]

signedmediaframework = shared_library(
    'signed-media-framework',
    signedmediaframework_sources,
    version : meson.project_version(),
    dependencies : signedmediaframework_deps,
    install : true,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
    signedmediaframework,
    name : 'signed-media-framework',
    description : 'ONVIF Signed Media Framework',
)
