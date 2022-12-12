subdir('base')

if gnutls_dep.found()
  subdir('gnutls')
endif

if backends.contains('openssl')
  if host_system == 'windows'
    crypt32_dep = cc.find_library('crypt32')
  endif

  subdir('openssl')
endif

if get_option('tests')
  subdir('tests')
endif
