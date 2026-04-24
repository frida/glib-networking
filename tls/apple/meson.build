sources = files(
  'apple-module.c',
  'gtlsbackend-apple.c',
  'gtlscertificate-apple.c',
  'gtlsconnection-apple.c',
  'gtlsclientconnection-apple.c',
  'gtlsserverconnection-apple.c',
  'gtlsdatabase-apple.c',
  'gtlsfiledatabase-apple.c',
)

incs = [top_inc]

apple_inc = include_directories('.')

# No third-party TLS library — everything is Apple frameworks.
apple_frameworks = [
  dependency('Security',   required: true),
  dependency('Network',    required: true),
  dependency('CoreFoundation', required: true),
]

deps = [
  gio_dep,
  glib_dep,
  gmodule_dep,
  gobject_dep,
  tlsbase_dep,
] + apple_frameworks

giomodules += 'gioapple'

module = shared_module(
  'gioapple',
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
  gioapple_lib = static_library('gioapple',
    objects: module.extract_all_objects(recursive: true),
    dependencies: deps,
      install: true,
    install_dir: gio_module_dir,
  )

  uninstalled_vapidir = meson.current_source_dir()
  uninstalled_variables = {
    'vapidir': uninstalled_vapidir,
  }
  installed_vapidir = get_option('prefix') / get_option('datadir') / 'vala' / 'vapi'
  installed_variables = {
    'vapidir': installed_vapidir,
  }

  pkg.generate(filebase: 'gioapple',
    name: 'gioapple',
    version: meson.project_version(),
    description: 'Network-related GIO module for GLib using Apple frameworks',
    requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0'],
    libraries: [gioapple_lib],
    variables: installed_variables,
    uninstalled_variables: uninstalled_variables,
  )
  install_headers(['gioapple.h'])
  install_data(['gioapple.vapi'], install_dir: installed_vapidir)

  gioapple_dep = declare_dependency(
    include_directories: include_directories('.'),
    link_with: gioapple_lib,
    variables: uninstalled_variables,
  )
  meson.override_dependency('gioapple', gioapple_dep)
endif

if meson.version().version_compare('>=0.58')
  env = environment()
  env.prepend('GIO_EXTRA_MODULES', meson.current_build_dir())
  meson.add_devenv(env)
endif
