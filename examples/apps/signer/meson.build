signer_sources = [
  'gst-plugin/gstsigning_defines.h',
  'main.c',
]

subdir('gst-plugin')

executable('signer',
  signer_sources,
  dependencies : [ gst_dep ],
  # link_with : signedmediaframework,
  install : true,
)
