sources = files(
  'openssl-module.c',
  'gtlsbackend-openssl.c',
  'gtlscertificate-openssl.c',
  'gtlsconnection-openssl.c',
  'gtlsserverconnection-openssl.c',
  'gtlsclientconnection-openssl.c',
  'gtlsdatabase-openssl.c',
  'gtlsfiledatabase-openssl.c',
  'gtlsbio.c',
  'openssl-util.c',
)

incs = [top_inc]

openssl_inc = include_directories('.')

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  openssl_dep,
  tlsbase_dep,
]

if gio_supports_plugins
  module = shared_module(
    'gioopenssl',
    sources: sources,
    include_directories: incs,
    dependencies: deps,
    link_args: module_ldflags,
    link_depends: symbol_map,
    name_suffix: module_suffix,
    install: true,
    install_dir: gio_module_dir,
  )
endif

if get_option('static_modules')
  static_module = static_library('gioopenssl',
    sources,
    objects: tlsbase.extract_all_objects(),
    c_args: ['-DG_IO_MODULE_BUILD_STATIC'],
    include_directories: incs,
    dependencies: deps,
    install: true,
    install_dir: gio_module_dir,
  )
  install_headers(['gioopenssl.h'])
  install_data(['gioopenssl.vapi'],
    install_dir: join_paths(get_option('datadir'), 'vala', 'vapi'))
  pkg.generate(filebase: 'gioopenssl',
    name: 'gioopenssl',
    version: meson.project_version(),
    description: 'Network-related GIO module for GLib using OpenSSL',
    requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0'],
    libraries: [static_module],
  )
endif
