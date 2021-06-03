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

if host_system == 'windows'
  deps += [
    crypt32_dep,
  ]
endif

giomodules += 'gioopenssl'

module = shared_module(
  'gioopenssl',
  sources: sources,
  include_directories: incs,
  dependencies: deps,
  link_args: module_ldflags,
  link_depends: symbol_map,
  name_suffix: module_suffix,
  install: build_shared,
  install_dir: gio_module_dir,
)

if build_static
  gioopenssl_lib = static_library('gioopenssl',
    objects: module.extract_all_objects(recursive: true),
    dependencies: deps,
    install: true,
    install_dir: gio_module_dir,
  )
  pkg.generate(filebase: 'gioopenssl',
    name: 'gioopenssl',
    version: meson.project_version(),
    description: 'Network-related GIO module for GLib using OpenSSL',
    requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0'],
    libraries: [gioopenssl_lib],
  )
  install_headers(['gioopenssl.h'])
  install_data(['gioopenssl.vapi'],
    install_dir: join_paths(get_option('datadir'), 'vala', 'vapi'))

  gioopenssl_dep = declare_dependency(link_with: gioopenssl_lib)
  meson.override_dependency('gioopenssl', gioopenssl_dep)
endif

if meson.version().version_compare('>=0.58')
  env = environment()
  env.prepend('GIO_EXTRA_MODULES', meson.current_build_dir())
  meson.add_devenv(env)
endif
