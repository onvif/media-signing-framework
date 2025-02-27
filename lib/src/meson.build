mediasigningframework_public_headers = files(
  'includes/onvif_media_signing_common.h',
  'includes/onvif_media_signing_helpers.h',
  'includes/onvif_media_signing_plugin.h',
  'includes/onvif_media_signing_signer.h',
  'includes/onvif_media_signing_validator.h',
)

mediasigningframework_sources = files(
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
mediasigningframework_sources += plugin_sources

omssrcinc = include_directories('.')
